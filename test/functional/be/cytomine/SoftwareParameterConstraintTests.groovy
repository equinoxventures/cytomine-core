package be.cytomine

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
import be.cytomine.test.Infos
import be.cytomine.test.http.SoftwareParameterConstraintAPI
import be.cytomine.utils.UpdateData
import grails.converters.JSON
import org.codehaus.groovy.grails.web.json.JSONArray
import org.codehaus.groovy.grails.web.json.JSONObject

class SoftwareParameterConstraintTests {

    void testListSoftwareParameterConstraintBySoftwareParameter() {
        SoftwareParameterConstraint parameterConstraint = BasicInstanceBuilder.getSoftwareParameterConstraint()
        def result = SoftwareParameterConstraintAPI.listBySoftwareParameter(parameterConstraint.softwareParameter.id, Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 200 == result.code
        def json = JSON.parse(result.data)
        assert json.collection instanceof JSONArray
        result = SoftwareParameterConstraintAPI.listBySoftwareParameter(-99,Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 404 == result.code
    }

    void testShowSoftwareParameterConstraint() {
        def result = SoftwareParameterConstraintAPI.show(BasicInstanceBuilder.getSoftwareParameterConstraint().id, Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 200 == result.code
        def json = JSON.parse(result.data)
        assert json instanceof JSONObject
    }

    void testAddSoftwareParameterConstraintCorrect() {
        def SoftwareParameterConstraintToAdd = BasicInstanceBuilder.getSoftwareParameterConstraintNotExist()
        def result = SoftwareParameterConstraintAPI.create(SoftwareParameterConstraintToAdd.encodeAsJSON(), Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 200 == result.code
        int idSoftwareParameterConstraint = result.data.id

        result = SoftwareParameterConstraintAPI.show(idSoftwareParameterConstraint, Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 200 == result.code
    }

    void testUpdateSoftwareParameterConstraintCorrect() {
        def sp = BasicInstanceBuilder.getSoftwareParameterConstraint()
        def data = UpdateData.createUpdateSet(sp,[value: ["OLDVALUE","NEWVALUE"]])
        def result = SoftwareParameterConstraintAPI.update(sp.id, data.postData,Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 200 == result.code
        def json = JSON.parse(result.data)
        assert json instanceof JSONObject
    }

    void testUpdateSoftwareParameterConstraintNotExist() {
        SoftwareParameterConstraint softwareParameterConstraintWithNewName = BasicInstanceBuilder.getSoftwareParameterConstraintNotExist()
        softwareParameterConstraintWithNewName.save(flush: true)
        SoftwareParameterConstraint softwareParameterConstraintToEdit = SoftwareParameterConstraint.get(softwareParameterConstraintWithNewName.id)
        def jsonSoftwareParameterConstraint = softwareParameterConstraintToEdit.encodeAsJSON()
        def jsonUpdate = JSON.parse(jsonSoftwareParameterConstraint)
        jsonUpdate.id = -99
        jsonSoftwareParameterConstraint = jsonUpdate.toString()
        def result = SoftwareParameterConstraintAPI.update(-99, jsonSoftwareParameterConstraint, Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 404 == result.code
    }

    void testUpdateSoftwareParameterConstraintWithBadSoftwareParameter() {
        SoftwareParameterConstraint softwareParameterConstraintToAdd = BasicInstanceBuilder.getSoftwareParameterConstraint()
        SoftwareParameterConstraint softwareParameterConstraintToEdit = SoftwareParameterConstraint.get(softwareParameterConstraintToAdd.id)
        def jsonSoftwareParameterConstraint = softwareParameterConstraintToEdit.encodeAsJSON()
        def jsonUpdate = JSON.parse(jsonSoftwareParameterConstraint)
        jsonUpdate.softwareParameter = -99
        jsonSoftwareParameterConstraint = jsonUpdate.toString()
        def result = SoftwareParameterConstraintAPI.update(softwareParameterConstraintToAdd.id, jsonSoftwareParameterConstraint, Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 400 == result.code
    }

    void testDeleteSoftwareParameterConstraint() {
        def softwareParameterConstraintToDelete = BasicInstanceBuilder.getSoftwareParameterConstraintNotExist()
        assert softwareParameterConstraintToDelete.save(flush: true)!= null
        def id = softwareParameterConstraintToDelete.id
        def result = SoftwareParameterConstraintAPI.delete(id, Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 200 == result.code

        def showResult = SoftwareParameterConstraintAPI.show(id, Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 404 == showResult.code
    }

    void testDeleteSoftwareParameterConstraintNotExist() {
        def result = SoftwareParameterConstraintAPI.delete(-99, Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 404 == result.code
    }

    void testEvaluateSoftwareParameterConstraint() {
        def softwareParameterConstraintToEvaluate = BasicInstanceBuilder.getSoftwareParameterConstraintNotExist()
        assert softwareParameterConstraintToEvaluate.save(flush: true)!= null
        def id = softwareParameterConstraintToEvaluate.id

        String current = "test"
        def result = SoftwareParameterConstraintAPI.evaluate(id, current, Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 200 == result.code
        def json = JSON.parse(result.data)
        assert false == json.result

        String expected = softwareParameterConstraintToEvaluate.value
        result = SoftwareParameterConstraintAPI.evaluate(id, expected, Infos.SUPERADMINLOGIN, Infos.SUPERADMINPASSWORD)
        assert 200 == result.code
        json = JSON.parse(result.data)
        assert true == json.result
    }
}
