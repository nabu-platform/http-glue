package be.nabu.libs.http.glue.auth;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.text.ParseException;

import javax.xml.bind.annotation.XmlRootElement;

import be.nabu.libs.authentication.TokenSerializerFactory;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.authentication.api.TokenSerializer;
import be.nabu.libs.authentication.impl.ImpersonateToken;
import be.nabu.libs.types.TypeUtils;
import be.nabu.libs.types.api.ComplexType;
import be.nabu.libs.types.binding.api.Window;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.java.BeanInstance;
import be.nabu.libs.types.java.BeanResolver;

public class ImpersonateTokenSerializer implements TokenSerializer<ImpersonateToken> {

	@Override
	public void serialize(OutputStream output, ImpersonateToken token) {
		SerializableImpersonateToken serializable = new SerializableImpersonateToken();
		serializable.setName(token.getName());
		serializable.setRealm(token.getRealm());

		if (token.getOriginalToken() != null) {
			TokenSerializer<Token> serializer = TokenSerializerFactory.getInstance().getSerializer(token.getOriginalToken());
			if (serializer == null) {
				throw new IllegalStateException("Can not find serializer for the original token: " + token.getOriginalToken());
			}
			ByteArrayOutputStream bytes = new ByteArrayOutputStream();
			serializer.serialize(bytes, token.getOriginalToken());
			serializable.setFactory(serializer.getName());
			serializable.setOriginalToken(bytes.toByteArray());
		}
		
		JSONBinding binding = new JSONBinding((ComplexType) BeanResolver.getInstance().resolve(SerializableImpersonateToken.class), Charset.forName("UTF-8"));
		try {
			binding.marshal(output, new BeanInstance<SerializableImpersonateToken>(serializable));
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public ImpersonateToken deserialize(InputStream input) {
		JSONBinding binding = new JSONBinding((ComplexType) BeanResolver.getInstance().resolve(SerializableImpersonateToken.class), Charset.forName("UTF-8"));
		try {
			SerializableImpersonateToken token = TypeUtils.getAsBean(binding.unmarshal(input, new Window[0]), SerializableImpersonateToken.class);
			
			Token original = null;
			
			if (token.getOriginalToken() != null) {
				TokenSerializer<Token> serializer = TokenSerializerFactory.getInstance().getSerializer(token.getName());
				if (serializer == null) {
					throw new IllegalStateException("Can not find serializer for token type: " + token.getName());
				}
				original = serializer.deserialize(new ByteArrayInputStream(token.getOriginalToken()));
			}
			return new ImpersonateToken(original, token.getRealm(), token.getName());
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String getName() {
		return "impersonate";
	}

	@Override
	public Class<ImpersonateToken> getTokenType() {
		return ImpersonateToken.class;
	}
	
	@XmlRootElement(name = "impersonateToken")
	public static class SerializableImpersonateToken {
		private String factory;
		private byte [] originalToken;
		private String name, realm;
		
		public byte [] getOriginalToken() {
			return originalToken;
		}
		public void setOriginalToken(byte [] originalToken) {
			this.originalToken = originalToken;
		}
		public String getFactory() {
			return factory;
		}
		public void setFactory(String factory) {
			this.factory = factory;
		}
		public String getName() {
			return name;
		}
		public void setName(String name) {
			this.name = name;
		}
		public String getRealm() {
			return realm;
		}
		public void setRealm(String realm) {
			this.realm = realm;
		}
		
	}
}
