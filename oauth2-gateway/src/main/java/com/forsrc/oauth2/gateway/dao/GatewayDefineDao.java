package com.forsrc.oauth2.gateway.dao;

import com.forsrc.oauth2.gateway.model.GatewayDefine;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface GatewayDefineDao extends JpaRepository<GatewayDefine, String> {

    List<GatewayDefine> findAll();

    GatewayDefine save(GatewayDefine gatewayDefine);

    void deleteById(String id);

    boolean existsById(String id);
}
