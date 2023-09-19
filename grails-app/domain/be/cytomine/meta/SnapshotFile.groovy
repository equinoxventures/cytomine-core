package be.cytomine.meta

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

import be.cytomine.CytomineDomain
import org.restapidoc.annotation.RestApiObject
import org.restapidoc.annotation.RestApiObjectField
import org.restapidoc.annotation.RestApiObjectFields

/**
 * A snapshot file to attach to any Cytomine domain
 */
@RestApiObject(name = "Snapshot file", description = "A snapshot file that may be attached to any Cytomine domain. Usefull to include file into description.")
class SnapshotFile extends CytomineDomain {

    /**
     * File data
     */
    byte[] data

    @RestApiObjectField(description = "Domain class name")
    String domainClassName

    @RestApiObjectField(description = "Domain id")
    Long domainIdent

    @RestApiObjectField(description = "File name with ext")
    String filename

    String key

    String location

    String previewUrl

    @RestApiObjectFields(params=[
        @RestApiObjectField(apiFieldName = "url", description = "URL to get this file",allowedType = "string",useForCreation = false)
    ])
    static transients = []

    static constraints = {
        domainClassName(nullable: false, blank:  false)
        key(nullable: true)
        location(nullable: true)
        previewUrl(nullable: true,maxSize: 1000)
    }
    static mapping = {
        id generator: "assigned"
        sort "id"
    }

    /**
     * Set annotation (storing class + id)
     * With groovy, you can do: this.annotation = ...
     * @param domain to add
     */
    public void setDomain(CytomineDomain domain) {
        domainClassName = domain.class.getName()
        domainIdent = domain.id
    }

    /**
     * Get annotation thanks to domainClassName and domainIdent
     * @return Annotation concerned with this prediction
     */
    public CytomineDomain retrieveCytomineDomain() {
        CytomineDomain domain = Class.forName(domainClassName, false, Thread.currentThread().contextClassLoader).read(domainIdent)
        domain
    }

    /**
     * Define fields available for JSON response
     * @param domain Domain source for json value
     * @return Map with fields (keys) and their values
     */
    static def getDataFromDomain(def domain) {
        def returnArray = CytomineDomain.getDataFromDomain(domain)
        returnArray['domainIdent'] = domain?.domainIdent
        returnArray['domainClassName'] = domain?.domainClassName
        returnArray['url'] = "/api/snapshotfile/${domain?.id}/download"
        returnArray['filename'] = domain?.filename
        returnArray['key'] = domain?.key
        returnArray['location'] = domain?.location
        returnArray['previewUrl'] = domain?.previewUrl

        return returnArray
    }
}

