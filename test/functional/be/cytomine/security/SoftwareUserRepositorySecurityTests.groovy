package be.cytomine.security

/*
* Copyright (c) 2009-2022. Authors: see NOTICE file.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import be.cytomine.test.BasicInstanceBuilder
import be.cytomine.test.Infos
import be.cytomine.processing.SoftwareUserRepository
import be.cytomine.test.http.SoftwareUserRepositoryAPI
import grails.converters.JSON

class SoftwareUserRepositorySecurityTests extends SecurityTestsAbstract {

    /**
     * Every user can read. Only admin can modify
     **/

    void testSoftwareUserRepositorySecurityForCytomineAdmin() {

        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)

        //Create new softwareuserrepo (user1)
        def result = SoftwareUserRepositoryAPI.create(BasicInstanceBuilder.getSoftwareUserRepositoryNotExist().encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        SoftwareUserRepository sur = result.data

        //check if admin user can access/update/delete
        assert (200 == SoftwareUserRepositoryAPI.show(sur.id,USERNAMEADMIN,PASSWORDADMIN).code)
        assert (true ==SoftwareUserRepositoryAPI.containsInJSONList(sur.id,JSON.parse(SoftwareUserRepositoryAPI.list(USERNAMEADMIN,PASSWORDADMIN).data)))
        assert (200 == SoftwareUserRepositoryAPI.update(sur.id,sur.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN).code)
        assert (200 == SoftwareUserRepositoryAPI.delete(sur.id,USERNAMEADMIN,PASSWORDADMIN).code)
    }

    void testSoftwareUserRepositorySecurityForSimpleUser() {

        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)
        //Get user1
        User user1 = BasicInstanceBuilder.getUser(USERNAME1,PASSWORD1)

        //Create new Software (user1)
        def result = SoftwareUserRepositoryAPI.create(BasicInstanceBuilder.getSoftwareUserRepositoryNotExist().encodeAsJSON(),USERNAME1,PASSWORD1)
        assert 403 == result.code
        result = SoftwareUserRepositoryAPI.create(BasicInstanceBuilder.getSoftwareUserRepositoryNotExist().encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        SoftwareUserRepository sur = result.data
        Infos.printRight(sur)
        //check if user 2 cannot access/update/delete
        assert (200 == SoftwareUserRepositoryAPI.show(sur.id,USERNAME1,PASSWORD1).code)
        assert (403 == SoftwareUserRepositoryAPI.update(sur.id,sur.encodeAsJSON(),USERNAME1,PASSWORD1).code)
        assert (403 == SoftwareUserRepositoryAPI.delete(sur.id,USERNAME1,PASSWORD1).code)

    }

    void testSoftwareUserRepositorySecurityForAnonymous() {

        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)

        //Create new Software (user1)
        def result = SoftwareUserRepositoryAPI.create(BasicInstanceBuilder.getSoftwareUserRepositoryNotExist().encodeAsJSON(),USERNAMEBAD,PASSWORDBAD)
        assert 401 == result.code
        result = SoftwareUserRepositoryAPI.create(BasicInstanceBuilder.getSoftwareUserRepositoryNotExist().encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        SoftwareUserRepository sur = result.data
        Infos.printRight(sur)
        //check if user 2 cannot access/update/delete
        assert (401 == SoftwareUserRepositoryAPI.show(sur.id,USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == SoftwareUserRepositoryAPI.list(USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == SoftwareUserRepositoryAPI.update(sur.id,sur.encodeAsJSON(),USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == SoftwareUserRepositoryAPI.delete(sur.id,USERNAMEBAD,PASSWORDBAD).code)
    }
}
