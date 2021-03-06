/*************************GO-LICENSE-START*********************************
 * Copyright 2014 ThoughtWorks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *************************GO-LICENSE-END***********************************/

package com.thoughtworks.go.server.security;

import com.thoughtworks.go.config.CaseInsensitiveString;
import com.thoughtworks.go.server.domain.Username;
import com.thoughtworks.go.server.service.SecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
public class AuthorityGranter {
    private final SecurityService securityService;

    @Autowired
    public AuthorityGranter(SecurityService securityService) {
        this.securityService = securityService;
    }

    public GrantedAuthority[] authorities(String username) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        checkAndAddSuperAdmin(username, authorities);
        checkAndAddGroupAdmin(username, authorities);
        checkAndAddTemplateAdmin(username, authorities);
        authorities.add(GoAuthority.ROLE_USER.asAuthority());
        return authorities.toArray(new GrantedAuthority[authorities.size()]);
    }

    private void checkAndAddTemplateAdmin(String username, List<GrantedAuthority> authorities) {
        if(securityService.isAuthorizedToViewAndEditTemplates(new Username(new CaseInsensitiveString(username)))) {
            authorities.add(GoAuthority.ROLE_TEMPLATE_SUPERVISOR.asAuthority());
        }
    }

    private void checkAndAddGroupAdmin(String username, List<GrantedAuthority> authorities) {
        if (securityService.isUserGroupAdmin(new Username(new CaseInsensitiveString(username)))) {
            authorities.add(GoAuthority.ROLE_GROUP_SUPERVISOR.asAuthority());
        }
    }

    private void checkAndAddSuperAdmin(String username, List<GrantedAuthority> authorities) {
        if (securityService.isUserAdmin(new Username(new CaseInsensitiveString(username)))) {
            authorities.add(GoAuthority.ROLE_SUPERVISOR.asAuthority());
        }
    }

    private List<GrantedAuthority> originalAsList(GrantedAuthority[] original) {
        return original == null ? new ArrayList<GrantedAuthority>() :  Arrays.asList(original);
    }
}
