package com.google.enterprise.sessionmanager;

import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.util.storage.StorageService;

public interface ArtifactStorageService extends StorageService<String, SAMLArtifactMapEntry> {

}
