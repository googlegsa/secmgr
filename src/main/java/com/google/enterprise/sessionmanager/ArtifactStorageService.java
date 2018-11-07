package com.google.enterprise.sessionmanager;

import java.util.Iterator;
import javax.inject.Inject;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.util.storage.StorageService;

public class ArtifactStorageService implements StorageService<String, SAMLArtifactMapEntry> {

  @Inject
  private RedisRepository redisRepository;

  @Override
  public boolean contains(String partition, String key) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Iterator<String> getPartitions() {
    throw new UnsupportedOperationException();
  }

  @Override
  public Iterator<String> getKeys(String partition) {
    throw new UnsupportedOperationException();
  }

  @Override
  public SAMLArtifactMapEntry get(String partition, String key) {
    return redisRepository.loadArtifact(key);
  }

  @Override
  public SAMLArtifactMapEntry put(String partition, String key, SAMLArtifactMapEntry samlArtifactMapEntry) {
    redisRepository.storeArtifact(key, samlArtifactMapEntry);
    return null;
  }

  @Override
  public SAMLArtifactMapEntry remove(String partition, String key) {
    redisRepository.remove(key);
    return null;
  }
}
