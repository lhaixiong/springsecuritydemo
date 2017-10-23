package com.lhx.springsecurity.config;

import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.jdbc.object.MappingSqlQuery;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * 查询资源和角色，并构建RequestMap
 *
 * @since 2017年10月23日 下午04:20:26
 * @author lhx
 */
public class JdbcRequestMapBulider extends JdbcDaoSupport {
    //查询资源和权限关系的sql语句
    private String resourceQuery = "";

    public String getResourceQuery() {
        return resourceQuery;
    }

    //查询资源
    public List<Resource> findResources() {
        ResourceMapping resourceMapping = new ResourceMapping(getDataSource(),
                resourceQuery);
        return resourceMapping.execute();
    }

    /**
     * buildRequestMap
     * @return
     */
    public LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> buildRequestMap() {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<>();

        List<Resource> resourceList = this.findResources();
        for (Resource resource : resourceList) {
            RequestMatcher requestMatcher = this.getRequestMatcher(resource.getUrl());
            List<ConfigAttribute> list = new ArrayList<ConfigAttribute>();
            list.add(new SecurityConfig(resource.getRole()));
            requestMap.put(requestMatcher, list);
        }
        return requestMap;
    }

    /**
     * 通过一个字符串地址构建一个AntPathRequestMatcher对象
     * @param url
     * @return
     */
    protected RequestMatcher getRequestMatcher(String url) {
        return new AntPathRequestMatcher(url);
    }

    public void setResourceQuery(String resourceQuery) {
        this.resourceQuery = resourceQuery;
    }

    /**
     * 资源内部类
     *
     * @since 2017年10月23日 下午04:29:06
     * @author lhx
     */
    private class Resource {
        /**
         * 资源访问的地址
         */
        private String url;
        /**
         * 所需要的权限
         */
        private String role;

        public Resource(String url, String role) {
            this.url = url;
            this.role = role;
        }

        public String getUrl() {
            return url;
        }

        public String getRole() {
            return role;
        }
    }

    private class ResourceMapping extends MappingSqlQuery {
        protected ResourceMapping(DataSource dataSource,
                                  String resourceQuery) {
            super(dataSource, resourceQuery);
            compile();
        }

        /**
         * 对结果集进行封装处理
         * @param rs
         * @param rownum
         * @return
         * @throws SQLException
         */
        protected Object mapRow(ResultSet rs, int rownum)
                throws SQLException {
            String url = rs.getString(1);
            String role = rs.getString(2);
            Resource resource = new Resource(url, role);
            return resource;
        }
    }
}
