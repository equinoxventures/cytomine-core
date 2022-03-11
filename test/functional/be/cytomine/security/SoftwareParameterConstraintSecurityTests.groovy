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

import be.cytomine.processing.SoftwareParameterConstraint
import be.cytomine.test.BasicInstanceBuilder
import be.cytomine.test.http.SoftwareParameterConstraintAPI
import grails.converters.JSON

class SoftwareParameterConstraintSecurityTests extends SecurityTestsAbstract {

    void testSoftwareParameterConstraintSecurityForCytomineAdmin() {

        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)

        //create
        SoftwareParameterConstraint softwareParameterConstraint = BasicInstanceBuilder.getSoftwareParameterConstraintNotExist()

        //Create new software param (user1)
        def result = SoftwareParameterConstraintAPI.create(softwareParameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        softwareParameterConstraint = result.data

        //check if admin user can access/update/delete
        assert (200 == SoftwareParameterConstraintAPI.show(softwareParameterConstraint.id,USERNAMEADMIN,PASSWORDADMIN).code)
        assert (true ==SoftwareParameterConstraintAPI.containsInJSONList(softwareParameterConstraint.id,JSON.parse(SoftwareParameterConstraintAPI.listBySoftwareParameter(softwareParameterConstraint.softwareParameter.id, USERNAMEADMIN,PASSWORDADMIN).data)))
        assert (200 == SoftwareParameterConstraintAPI.update(softwareParameterConstraint.id,softwareParameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN).code)
        assert (200 == SoftwareParameterConstraintAPI.evaluate(softwareParameterConstraint.id,"test", USERNAMEADMIN,PASSWORDADMIN).code)
        assert (200 == SoftwareParameterConstraintAPI.delete(softwareParameterConstraint.id,USERNAMEADMIN,PASSWORDADMIN).code)
    }

    void testSoftwareParameterConstraintSecurityInjection() {
        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)

        SoftwareParameterConstraint softwareParameterConstraint = BasicInstanceBuilder.getSoftwareParameterConstraintNotExist()

        def result = SoftwareParameterConstraintAPI.create(softwareParameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        softwareParameterConstraint = result.data

        String fileName = "/tmp/RH"+(new Random()).nextInt()

        assert !(new File(fileName).exists())
        assert (200 == SoftwareParameterConstraintAPI.show(softwareParameterConstraint.id,USERNAMEADMIN,PASSWORDADMIN).code)
        assert (400 == SoftwareParameterConstraintAPI.evaluate(softwareParameterConstraint.id,"\";new File(\""+fileName+"\").createNewFile();\" x", USERNAMEADMIN,PASSWORDADMIN).code)
        assert !(new File(fileName).exists())
        new File(fileName).createNewFile()
        assert (new File(fileName).exists())
        assert (400 == SoftwareParameterConstraintAPI.evaluate(softwareParameterConstraint.id,"\";new File(\""+fileName+"\").delete();\" x", USERNAMEADMIN,PASSWORDADMIN).code)
        assert (new File(fileName).exists())
        new File(fileName).delete()
        assert !(new File(fileName).exists())
    }

    void testSoftwareParameterConstraintSecurityForSimpleUser() {

        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)
        //Get user1
        User user1 = BasicInstanceBuilder.getUser(USERNAME1,PASSWORD1)

        def softwareParameterConstraint = BasicInstanceBuilder.getSoftwareParameterConstraintNotExist()

        //Create new software param
        def result = SoftwareParameterConstraintAPI.create(softwareParameterConstraint.encodeAsJSON(),USERNAME1,PASSWORD1)
        assert 403 == result.code
        result = SoftwareParameterConstraintAPI.create(softwareParameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        softwareParameterConstraint = result.data
        //check if user 2 cannot access/update/delete
        assert (200 == SoftwareParameterConstraintAPI.show(softwareParameterConstraint.id,USERNAME1,PASSWORD1).code)
        assert (true ==SoftwareParameterConstraintAPI.containsInJSONList(softwareParameterConstraint.id,JSON.parse(SoftwareParameterConstraintAPI.listBySoftwareParameter(softwareParameterConstraint.softwareParameter.id, USERNAME1,PASSWORD1).data)))
        assert (403 == SoftwareParameterConstraintAPI.update(softwareParameterConstraint.id,softwareParameterConstraint.encodeAsJSON(),USERNAME1,PASSWORD1).code)
        assert (200 == SoftwareParameterConstraintAPI.evaluate(softwareParameterConstraint.id,"test", USERNAME1,PASSWORD1).code)
        assert (403 == SoftwareParameterConstraintAPI.delete(softwareParameterConstraint.id,USERNAME1,PASSWORD1).code)
    }

    void testSoftwareParameterConstraintSecurityForAnonymous() {

        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)

        //Create new software param
        def softwareParameterConstraint = BasicInstanceBuilder.getSoftwareParameterConstraintNotExist()

        def result = SoftwareParameterConstraintAPI.create(softwareParameterConstraint.encodeAsJSON(),USERNAMEBAD,PASSWORDBAD)
        assert 401 == result.code
        result = SoftwareParameterConstraintAPI.create(softwareParameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        softwareParameterConstraint = result.data
        //check if user 2 cannot access/update/delete
        assert (401 == SoftwareParameterConstraintAPI.show(softwareParameterConstraint.id,USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == SoftwareParameterConstraintAPI.listBySoftwareParameter(softwareParameterConstraint.softwareParameter.id, USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == SoftwareParameterConstraintAPI.update(softwareParameterConstraint.id,softwareParameterConstraint.encodeAsJSON(),USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == SoftwareParameterConstraintAPI.evaluate(softwareParameterConstraint.id,"test", USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == SoftwareParameterConstraintAPI.delete(softwareParameterConstraint.id,USERNAMEBAD,PASSWORDBAD).code)
    }
}
