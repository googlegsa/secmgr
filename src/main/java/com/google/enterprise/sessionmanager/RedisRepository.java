package com.google.enterprise.sessionmanager;

import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import io.lettuce.core.RedisClient;
import io.lettuce.core.SetArgs;
import io.lettuce.core.SetArgs.Builder;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import io.lettuce.core.codec.RedisCodec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.logging.Logger;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;

@Singleton
public class RedisRepository {

  public static final long SESSION_TTL_SEC = SecurityManagerUtil.getGsaSessionIdleMillis() / 1000;
  public static final SetArgs SESSION_TTL = Builder.ex(SESSION_TTL_SEC);
  public static final SetArgs ARTIFACT_TTL = Builder.ex(SamlSharedData.DEFAULT_ARTIFACT_LIFETIME_MS / 1000);
  private RedisCommands<String, Object> redisCommands;

  private static final Logger logger = Logger.getLogger(RedisRepository.class.getName());

  @Inject
  public RedisRepository(@Named("redis-connection-string") String redisConnectionString) {
    RedisClient redisClient = RedisClient.create(redisConnectionString);
    StatefulRedisConnection<String, Object> connect = redisClient.connect(new SerializedObjectCodec());
    redisCommands = connect.sync();
  }

  public void storeSession(AuthnSession session, long sessionIdleMillis) {
    redisCommands.set(session.getSessionId(), session, Builder.ex(sessionIdleMillis / 1000));
  }

  public AuthnSession loadSession(String sessionId) {
    return (AuthnSession) redisCommands.get(sessionId);
  }

  public void updateSessionTTL(AuthnSession authnSession) {
    redisCommands.expire(authnSession.getSessionId(), SESSION_TTL_SEC);
  }

  public void storeArtifact(String artifactId, SAMLArtifactMapEntry artifact) {
    redisCommands.set(artifactId, artifact, ARTIFACT_TTL);
  }

  public SAMLArtifactMapEntry loadArtifact(String artifactId) {
    return (SAMLArtifactMapEntry) redisCommands.get(artifactId);
  }

  public void remove(String artifactId) {
    redisCommands.del(artifactId);
  }


  public class SerializedObjectCodec implements RedisCodec<String, Object> {
    private Charset charset = Charset.forName("UTF-8");

    @Override
    public String decodeKey(ByteBuffer bytes) {
      return charset.decode(bytes).toString();
    }

    @Override
    public Object decodeValue(ByteBuffer bytes) {
      try {
        byte[] array = new byte[bytes.remaining()];
        bytes.get(array);
        ObjectInputStream is = new ObjectInputStream(new ByteArrayInputStream(array));
        return is.readObject();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public ByteBuffer encodeKey(String key) {
      return charset.encode(key);
    }

    @Override
    public ByteBuffer encodeValue(Object value) {
      try {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(bytes);
        os.writeObject(value);
        byte[] array = bytes.toByteArray();
        logger.info("Session size in bytes for " + value.getClass().toString() + " : "
            + array.length);
        return ByteBuffer.wrap(array);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
