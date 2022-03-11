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

class ParameterConstraintUrlMappings {

    static mappings = {
        "/api/parameter_constraint.$format"(controller: "restParameterConstraint") {
            action = [GET: "list"]
        }
        "/api/parameter_constraint/$id.$format"(controller: "restParameterConstraint") {
            action = [GET: "show"]
        }

        // currently disabled. HOW TO avoid to add or update object with expression "new File(\"/tmp/test\").createNewFile();"   ... or worse !
        /*"/api/parameter_constraint.$format"(controller: "restParameterConstraint") {
            action = [GET: "list", POST: "add"]
        }
        "/api/parameter_constraint/$id.$format"(controller: "restParameterConstraint") {
            action = [GET: "show", PUT: "update", DELETE: "delete"]
        }*/
    }

}