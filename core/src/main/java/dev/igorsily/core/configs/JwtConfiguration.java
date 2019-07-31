package dev.igorsily.core.configs;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt.config")
public class JwtConfiguration {

    private String urlLogin = "/login/**";

    @NestedConfigurationProperty
    private Header header = new Header();

    private int expiration = 3600;

    private String privateKey = "8r94FS8dBhxnusA3w0UaFwMQOXChx7Dh";

    private String type = "encrypted";

    static class Header{
        private String name = "Authorization";
        private String prefix = "Bearer";

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getPrefix() {
            return prefix;
        }

        public void setPrefix(String prefix) {
            this.prefix = prefix;
        }
    }

    public String getUrlLogin() {
        return urlLogin;
    }

    public void setUrlLogin(String urlLogin) {
        this.urlLogin = urlLogin;
    }

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
    }

    public int getExpiration() {
        return expiration;
    }

    public void setExpiration(int expiration) {
        this.expiration = expiration;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
