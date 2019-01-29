// Copyright 2008 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.secmgr.saml;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.XmlUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.util.C;

import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.AbstractObservableMetadataProvider;
import org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ObservableMetadataProvider;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.CDATASection;
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.EntityReference;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.ProcessingInstruction;
import org.w3c.dom.Text;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Logger;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.servlet.http.HttpServletRequest;

/**
 * An abstract interface to the SAML metadata configuration.  Tracks a given
 * metadata file and keeps it up to date.  Also rewrites the metadata so it uses
 * the correct hostname.
 */
@ThreadSafe
public class Metadata {
  private static final Logger logger = Logger.getLogger(Metadata.class.getName());
  @VisibleForTesting
  static final int CACHE_SIZE = 32;
  private static final Object METADATA_FILE_LOCK = new Object();

  /**
   * Legacy SAML metadata markers that we need to support.
   *
   * The current metadata markers are specified in MetadataEditor.
   */
  public static final String PRE_70_ENTITY_ID =
      "http://google.com/enterprise/gsa/${ENT_CONFIG_NAME}";
  public static final String GSA_70_ENTITY_ID = "http://google.com/enterprise/gsa";
  public static final String GSA_72_ENTITY_ID = "${GSA_ENTITY_ID}";
  public static final String GSA_72_SECMGR_SUFFIX = "/security-manager";

  @GuardedBy("METADATA_FILE_LOCK")
  private static File overrideMetadataFile = null;

  private static final LoadingCache<String, Metadata> CACHE
      = CacheBuilder.newBuilder().maximumSize(CACHE_SIZE).build(
          CacheLoader.from(
              new Function<String, Metadata>() {
                @Override
                public Metadata apply(String urlPrefix) {
                  return new Metadata(urlPrefix);
                }
              }));

  private final MyProvider provider;

  // TODO: refactor this to use a base URI and resolve the partial URI
  // string in the metadata with respect to this base URI.  For example, a
  // pattern "https://$$GSA$$:1234/foo/bar" in the metadata would be resolved as
  // baseUri.resolve("foo/bar") after the boilerplate was stripped out.
  private Metadata(String urlPrefix) {
    try {
      provider = new MyProvider(OpenSamlUtil.getMetadataFromFile(getMetadataFile()), urlPrefix,
          SecurityManagerUtil.getConfiguredEntityId());
      provider.initialize();
    } catch (MetadataProviderException e) {
      throw new LocalExceptionTunnel(new IOException(e));
    }
  }

  private static final class LocalExceptionTunnel extends RuntimeException {

    LocalExceptionTunnel(IOException exception) {
      super(exception);
    }

    IOException getException() {
      return (IOException) getCause();
    }
  }

  private static File getMetadataFile() {
    synchronized (METADATA_FILE_LOCK) {
      if (overrideMetadataFile != null) {
        return overrideMetadataFile;
      }
    }
    try {
      return FileUtil.getContextFile(ConfigSingleton.getSamlMetadataFilename());
    } catch (IOException e) {
      throw new LocalExceptionTunnel(e);
    }
  }

  @VisibleForTesting
  static void setMetadataFile(File metadataFile) {
    synchronized (METADATA_FILE_LOCK) {
      overrideMetadataFile = metadataFile;
    }
  }

  public static Metadata getInstance(URI uri)
      throws IOException {
    URI prefixUri;
    try {
      prefixUri = new URI(uri.getScheme(), uri.getHost(), null, null);
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(e);
    }
    return getInstance(prefixUri.toString());
  }

  public static Metadata getInstance(HttpServletRequest request)
      throws IOException {
    URI uri = HttpUtil.getRequestUri(request, false);
    return getInstance(uri);
  }

  /**
   * Gets a metadata instance that isn't specialized for any particular host.
   * The URLs in this instance aren't valid and should not be used.
   */
  public static Metadata getUnspecializedInstance()
      throws IOException {
    return getInstance("dummy://example.net");
  }

  @VisibleForTesting
  public static Metadata getInstanceForTest()
      throws IOException {
    return getInstanceForTest("localhost");
  }

  @VisibleForTesting
  public static Metadata getInstanceForTest(String securityManagerHost)
      throws IOException {
    return getInstance("http://" + securityManagerHost);
  }

  /**
   * Forces refresh of cached metadata.
   */
  @VisibleForTesting
  void refresh()
      throws IOException {
    try {
      provider.refresh();
    } catch (MetadataProviderException e) {
      throw new IOException(e);
    }
  }

  private static Metadata getInstance(String urlPrefix)
      throws IOException {
    try {
      return CACHE.apply(urlPrefix);
    } catch (LocalExceptionTunnel e) {
      throw e.getException();
    }
  }

  public MetadataProvider getProvider() {
    return provider;
  }

  public EntitiesDescriptor getMetadata()
      throws IOException {
    XMLObject root;
    try {
      root = provider.getMetadata();
    } catch (MetadataProviderException e) {
      throw new IOException(e);
    }
    if (root instanceof EntitiesDescriptor) {
      return (EntitiesDescriptor) root;
    }
    throw new IOException("Malformed SAML metadata");
  }

  public EntityDescriptor getEntity(String id)
      throws IOException {
    return getEntity(id, provider);
  }

  public static EntityDescriptor getEntity(String id, MetadataProvider provider)
      throws IOException {
    EntityDescriptor entity = findEntity(id, provider);
    Preconditions.checkArgument(entity != null, "Unknown entity ID: %s", id);
    return entity;
  }

  public static EntityDescriptor findEntity(String id, MetadataProvider provider)
      throws IOException {
    try {
      return provider.getEntityDescriptor(id);
    } catch (MetadataProviderException e) {
      throw new IOException(e);
    }
  }

  public EntityDescriptor getGsaEntity()
      throws IOException {
    return getEntityById(MetadataEditor.GSA_ID_FOR_ENTITY);
  }

  public static String getGsaEntityId() {
    try {
      return getUnspecializedInstance().getGsaEntity().getEntityID();
    } catch (IOException e) {
      throw new IllegalStateException("Unable to read SAML metadata: ", e);
    }
  }

  public EntityDescriptor getSmEntity()
      throws IOException {
    return getEntityById(MetadataEditor.SECMGR_ID_FOR_ENTITY);
  }

  public static String getSmEntityId() {
    try {
      return getUnspecializedInstance().getSmEntity().getEntityID();
    } catch (IOException e) {
      throw new IllegalStateException("Unable to read SAML metadata: ", e);
    }
  }

  private EntityDescriptor getEntityById(String id)
      throws IOException {
    for (EntityDescriptor e : getMetadata().getEntityDescriptors()) {
      if (id.equals(e.getID())) {
        return e;
      }
    }
    throw new IllegalStateException("Can't find entity descriptor with id: " + id);
  }

  /**
   * This class implements a wrapper around an OpenSAML
   * ObservableMetadataProvider that customizes the metadata for a particular
   * host.  When the metadata is updated, as when the configuration file is
   * changed, this provider notices that, gets the updated metadata, and
   * customizes it.  To speed things up a bit, the customized metadata is
   * cached, so it need not be customized every time.
   */
  private static class MyProvider
      extends AbstractObservableMetadataProvider
      implements ObservableMetadataProvider.Observer {

    final AbstractReloadingMetadataProvider wrappedProvider;
    final String urlPrefix;
    final String configuredEntityId;
    XMLObject savedMetadata;

    MyProvider(AbstractReloadingMetadataProvider wrappedProvider, String urlPrefix,
        String configuredEntityId) {
      super();
      this.wrappedProvider = wrappedProvider;
      this.urlPrefix = urlPrefix;
      this.configuredEntityId = configuredEntityId;
      savedMetadata = null;

      wrappedProvider.getObservers().add(this);
    }

    @Override
    public synchronized void onEvent(MetadataProvider provider) {
      logger.info("Clearing cached metadata");
      savedMetadata = null;
      emitChangeEvent();
    }

    @Override
    public void doInitialization()
        throws MetadataProviderException {
      wrappedProvider.initialize();
    }

    @Override
    public synchronized XMLObject doGetMetadata()
        throws MetadataProviderException {
      // This will call onEvent if the file has changed:
      XMLObject rawMetadata = wrappedProvider.getMetadata();
      if (savedMetadata == null) {
        try {
          savedMetadata = OpenSamlUtil.unmarshallXmlObject(
              substituteTopLevel(
                  OpenSamlUtil.marshallXmlObject(rawMetadata)));
        } catch (MarshallingException e) {
          throw new MetadataProviderException(e);
        } catch (UnmarshallingException e) {
          throw new MetadataProviderException(e);
        }
      }
      return savedMetadata;
    }

    /**
     * Forces refresh of cached metadata.
     */
    @VisibleForTesting
    synchronized void refresh()
        throws MetadataProviderException {
      wrappedProvider.refresh();
    }

    Element substituteTopLevel(Element element) {
      Document doc = XmlUtil.getInstance()
          .makeDocument(element.getNamespaceURI(), element.getTagName(), null);
      Element newElement = doc.getDocumentElement();
      substituteInNodeChildren(element, newElement, doc);
      return newElement;
    }

    void substituteInNodeChildren(Node node, Node newNode, Document doc) {
      if (node instanceof Element) {
        NamedNodeMap attrs = node.getAttributes();
        NamedNodeMap newAttrs = newNode.getAttributes();
        for (int i = 0; i < attrs.getLength(); i++) {
          Node attr = attrs.item(i);
          Node newAttr = doc.createAttributeNS(attr.getNamespaceURI(), attr.getNodeName());
          newAttr.setNodeValue(substituteInString(attr.getNodeValue()));
          newAttrs.setNamedItemNS(newAttr);
        }
      }
      for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling()) {
        Node newChild = substituteInNode(child, doc);
        substituteInNodeChildren(child, newChild, doc);
        newNode.appendChild(newChild);
      }
    }

    Node substituteInNode(Node node, Document doc) {
      if (node instanceof Element) {
        return doc.createElementNS(node.getNamespaceURI(), node.getNodeName());
      } else if (node instanceof Text) {
        return doc.createTextNode(substituteInString(node.getNodeValue()));
      } else if (node instanceof CDATASection) {
        return doc.createCDATASection(node.getNodeValue());
      } else if (node instanceof Comment) {
        return doc.createComment(node.getNodeValue());
      } else if (node instanceof EntityReference) {
        return doc.createEntityReference(node.getNodeName());
      } else if (node instanceof ProcessingInstruction) {
        return doc.createProcessingInstruction(node.getNodeName(), node.getNodeValue());
      } else {
        throw new IllegalArgumentException("Unknown node type: " + node.getNodeType());
      }
    }

    String substituteInString(String original) {
      if (original == null) { return original; }
      String pattern = "https://" + MetadataEditor.GSA_HOST_MARKER;
      if (original.startsWith(pattern)) {
        return original.replace(pattern, urlPrefix);
      }
      pattern = "http://" + MetadataEditor.GSA_HOST_MARKER;
      if (original.startsWith(pattern)) {
        return original.replace(pattern, urlPrefix);
      }

      // this is the substitution for a config that's in the current version
      if (original.contains(MetadataEditor.GSA_ENTITY_ID_MARKER)) {
        return original.replace(MetadataEditor.GSA_ENTITY_ID_MARKER,
            C.entityIdForGsa(configuredEntityId));
      }
      if (original.contains(MetadataEditor.SECMGR_ENTITY_ID_MARKER)) {
        return original.replace(MetadataEditor.SECMGR_ENTITY_ID_MARKER,
            C.entityIdForSecMgr(configuredEntityId));
      }

      // legacy saml-metadata.xml file support - instead of looking for the current
      // entity marker, look for the entity id or marker that was used in that version
      // and replace it with the correct GSA entity
      if (original.equals(PRE_70_ENTITY_ID)
          || original.equals(GSA_70_ENTITY_ID)
          || original.equals(GSA_72_ENTITY_ID)) {
        return C.entityIdForGsa(configuredEntityId);
      }
      if (original.equals(PRE_70_ENTITY_ID + GSA_72_SECMGR_SUFFIX)
          || original.equals(GSA_70_ENTITY_ID + GSA_72_SECMGR_SUFFIX)
          || original.equals(GSA_72_ENTITY_ID + GSA_72_SECMGR_SUFFIX)) {
        return C.entityIdForSecMgr(configuredEntityId);
      }

      return original;
    }
  }
}
