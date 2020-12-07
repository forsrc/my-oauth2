package com.forsrc.oauth2.gateway.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.List;

@Entity
@Table(name = "gateway_define", indexes = {
        @Index(name = "index_gateway_define_uri", columnList = "uri")})
@JsonIgnoreProperties(value = {"hibernateLazyInitializer", "handler", "fieldHandler"})
public class GatewayDefine implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private String id;

    @Column(name = "uri", length = 500, nullable = false, columnDefinition = "VARCHAR(1) DEFAULT ''")
    private String uri;

    @Column(name = "predicates", length = 2000, nullable = false, columnDefinition = "VARCHAR(1) DEFAULT ''")
    private String predicates;

    @Column(name = "filters", length = 2000, nullable = false, columnDefinition = "VARCHAR(1) DEFAULT ''")
    private String filters;

    @Column(name = "enabled", length = 1, nullable = false, columnDefinition = "INT DEFAULT 1")
    private Integer enabled;

    @Column(name = "create_at", insertable = false, updatable = false, nullable = false, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    @Temporal(TemporalType.TIMESTAMP)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private Date createAt;
    @Column(name = "update_at", insertable = false, updatable = true, nullable = false, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    @Temporal(TemporalType.TIMESTAMP)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private Date updateAt;
    @Column(name = "version", insertable = false, updatable = true, nullable = false, columnDefinition = "INT DEFAULT 0")
    @Version
    private int version;

    @PrePersist
    protected void onCreateAt() {
        this.createAt = new Date();
    }

    @PreUpdate
    protected void onUpdateAt() {
        this.updateAt = new Date();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getPredicates() {
        return this.predicates;
    }

    public void setPredicates(String predicates) {
        this.predicates = predicates;
    }

    public Integer getEnabled() {
        return enabled;
    }

    public void setEnabled(Integer enabled) {
        this.enabled = enabled;
    }

    public Date getCreateAt() {
        return createAt;
    }

    public void setCreateAt(Date createAt) {
        this.createAt = createAt;
    }

    public Date getUpdateAt() {
        return updateAt;
    }

    public void setUpdateAt(Date updateAt) {
        this.updateAt = updateAt;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public List<PredicateDefinition> getPredicateDefinition() {
        if (this.predicates != null) {
            ObjectMapper objectMapper = new ObjectMapper();
            TypeFactory typeFactory = objectMapper.getTypeFactory();
            List<PredicateDefinition> predicateDefinitionList = null;
            try {
                predicateDefinitionList = objectMapper.readValue(this.predicates, typeFactory.constructCollectionType(List.class, PredicateDefinition.class));
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }

            return predicateDefinitionList;
        } else {
            return null;
        }
    }

    public String getFilters() {
        return filters;
    }

    public void setFilters(String filters) {
        this.filters = filters;
    }

    public List<FilterDefinition> getFilterDefinition() {
        if (this.filters != null) {
            ObjectMapper objectMapper = new ObjectMapper();
            TypeFactory typeFactory = objectMapper.getTypeFactory();
            List<FilterDefinition> filterDefinitionList = null;
            try {
                filterDefinitionList = objectMapper.readValue(this.filters, typeFactory.constructCollectionType(List.class, FilterDefinition.class));
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }
            return filterDefinitionList;
        } else {
            return null;
        }
    }

    @Override
    public String toString() {
        return "GatewayDefine{" +
                "id='" + id + '\'' +
                ", uri='" + uri + '\'' +
                ", predicates='" + predicates + '\'' +
                ", filters='" + filters + '\'' +
                '}';
    }
}
