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

import be.cytomine.processing.ParameterConstraint
import be.cytomine.test.BasicInstanceBuilder
import be.cytomine.test.http.ParameterConstraintAPI
import grails.converters.JSON

class ParameterConstraintSecurityTests extends SecurityTestsAbstract {

    void testParameterConstraintSecurityForCytomineAdmin() {

        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)

/*
        //create
        ParameterConstraint parameterConstraint = BasicInstanceBuilder.getParameterConstraintNotExist()

        //Create new software param (user1)
        def result = ParameterConstraintAPI.create(parameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        parameterConstraint = result.data

        //check if admin user can access/update/delete
        assert (200 == ParameterConstraintAPI.show(parameterConstraint.id,USERNAMEADMIN,PASSWORDADMIN).code)
        assert (true ==ParameterConstraintAPI.containsInJSONList(parameterConstraint.id,JSON.parse(ParameterConstraintAPI.list(USERNAMEADMIN,PASSWORDADMIN).data)))
        assert (200 == ParameterConstraintAPI.update(parameterConstraint.id,parameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN).code)
        assert (200 == ParameterConstraintAPI.delete(parameterConstraint.id,USERNAMEADMIN,PASSWORDADMIN).code)
*/

        //create
        ParameterConstraint parameterConstraint = BasicInstanceBuilder.getParameterConstraintNotExist(true)

        //check if admin user can access/update/delete
        assert (200 == ParameterConstraintAPI.show(parameterConstraint.id,USERNAMEADMIN,PASSWORDADMIN).code)
        assert (true ==ParameterConstraintAPI.containsInJSONList(parameterConstraint.id,JSON.parse(ParameterConstraintAPI.list(USERNAMEADMIN,PASSWORDADMIN).data)))
        assert (404 == ParameterConstraintAPI.update(parameterConstraint.id,parameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN).code)
        assert (404 == ParameterConstraintAPI.delete(parameterConstraint.id,USERNAMEADMIN,PASSWORDADMIN).code)
    }

    /*void testParameterConstraintSecurityInjection() {
        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)

        ParameterConstraint parameterConstraint = BasicInstanceBuilder.getParameterConstraintNotExist()

        String fileName = "/tmp/RH"+(new Random()).nextInt()

        parameterConstraint.expression = "new File(\""+fileName+"\").createNewFile();"

        def result = ParameterConstraintAPI.create(parameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        parameterConstraint = result.data

        SoftwareParameterConstraint softwareParameterConstraint = BasicInstanceBuilder.getSoftwareParameterConstraintNotExist()
        softwareParameterConstraint.parameterConstraint = parameterConstraint


        result = SoftwareParameterConstraintAPI.create(softwareParameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        softwareParameterConstraint = result.data

        assert !(new File(fileName).exists())
        assert (200 == SoftwareParameterConstraintAPI.show(softwareParameterConstraint.id,USERNAMEADMIN,PASSWORDADMIN).code)
        assert (200 == SoftwareParameterConstraintAPI.evaluate(softwareParameterConstraint.id,"bar", USERNAMEADMIN,PASSWORDADMIN).code)
        assert false
        assert !(new File(fileName).exists())
        new File(fileName).createNewFile()
        assert (new File(fileName).exists())
        assert (400 == SoftwareParameterConstraintAPI.evaluate(softwareParameterConstraint.id,"\";new File(\""+fileName+"\").delete();\" x", USERNAMEADMIN,PASSWORDADMIN).code)
        assert (new File(fileName).exists())
        new File(fileName).delete()
        assert !(new File(fileName).exists())
    }*/

    void testParameterConstraintSecurityForSimpleUser() {

        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)
        //Get user1
        User user1 = BasicInstanceBuilder.getUser(USERNAME1,PASSWORD1)

/*
        def parameterConstraint = BasicInstanceBuilder.getParameterConstraintNotExist()

        //Create new software param
        def result = ParameterConstraintAPI.create(parameterConstraint.encodeAsJSON(),USERNAME1,PASSWORD1)
        assert 403 == result.code
        result = ParameterConstraintAPI.create(parameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        parameterConstraint = result.data
        //check if user 2 cannot access/update/delete
        assert (200 == ParameterConstraintAPI.show(parameterConstraint.id,USERNAME1,PASSWORD1).code)
        assert (ParameterConstraintAPI.containsInJSONList(parameterConstraint.id,JSON.parse(ParameterConstraintAPI.list(USERNAME1,PASSWORD1).data)))
        assert (403 == ParameterConstraintAPI.update(parameterConstraint.id,parameterConstraint.encodeAsJSON(),USERNAME1,PASSWORD1).code)
        assert (403 == ParameterConstraintAPI.delete(parameterConstraint.id,USERNAME1,PASSWORD1).code)
*/
        //Create new software param
        def parameterConstraint = BasicInstanceBuilder.getParameterConstraintNotExist(true)
        //check if user 2 cannot access/update/delete
        assert (200 == ParameterConstraintAPI.show(parameterConstraint.id,USERNAME1,PASSWORD1).code)
        assert (ParameterConstraintAPI.containsInJSONList(parameterConstraint.id,JSON.parse(ParameterConstraintAPI.list(USERNAME1,PASSWORD1).data)))
        assert (404 == ParameterConstraintAPI.update(parameterConstraint.id,parameterConstraint.encodeAsJSON(),USERNAME1,PASSWORD1).code)
        assert (404 == ParameterConstraintAPI.delete(parameterConstraint.id,USERNAME1,PASSWORD1).code)
    }

    void testParameterConstraintSecurityForAnonymous() {

        //Get admin user
        User admin = BasicInstanceBuilder.getSuperAdmin(USERNAMEADMIN,PASSWORDADMIN)

/*
        //Create new software param
        def parameterConstraint = BasicInstanceBuilder.getParameterConstraintNotExist()

        def result = ParameterConstraintAPI.create(parameterConstraint.encodeAsJSON(),USERNAMEBAD,PASSWORDBAD)
        assert 401 == result.code
        result = ParameterConstraintAPI.create(parameterConstraint.encodeAsJSON(),USERNAMEADMIN,PASSWORDADMIN)
        assert 200 == result.code
        parameterConstraint = result.data
        //check if user 2 cannot access/update/delete
        assert (401 == ParameterConstraintAPI.show(parameterConstraint.id,USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == ParameterConstraintAPI.list(USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == ParameterConstraintAPI.update(parameterConstraint.id,parameterConstraint.encodeAsJSON(),USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == ParameterConstraintAPI.delete(parameterConstraint.id,USERNAMEBAD,PASSWORDBAD).code)
*/
        //Create new software param
        def parameterConstraint = BasicInstanceBuilder.getParameterConstraintNotExist(true)

        assert (401 == ParameterConstraintAPI.show(parameterConstraint.id,USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == ParameterConstraintAPI.list(USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == ParameterConstraintAPI.update(parameterConstraint.id,parameterConstraint.encodeAsJSON(),USERNAMEBAD,PASSWORDBAD).code)
        assert (401 == ParameterConstraintAPI.delete(parameterConstraint.id,USERNAMEBAD,PASSWORDBAD).code)
    }
}
