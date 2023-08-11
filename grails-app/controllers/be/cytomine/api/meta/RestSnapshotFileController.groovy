package be.cytomine.api.meta

import be.cytomine.Exception.InvalidRequestException
import be.cytomine.Exception.NotModifiedException
import be.cytomine.Exception.ObjectNotFoundException
import be.cytomine.Exception.ServerException

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

import be.cytomine.api.RestController
import be.cytomine.image.AbstractImage
import be.cytomine.image.SliceInstance
import be.cytomine.meta.Configuration
import be.cytomine.project.Project
import be.cytomine.AnnotationDomain
import be.cytomine.CytomineDomain
import be.cytomine.Exception.WrongArgumentException
import be.cytomine.meta.SnapshotFile
import be.cytomine.security.SecUser
import be.cytomine.utils.ImageResponse
import com.vividsolutions.jts.geom.Geometry
import com.vividsolutions.jts.io.WKTReader
import grails.converters.JSON
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovyx.net.http.ContentType
import groovyx.net.http.HTTPBuilder
import groovyx.net.http.HttpResponseDecorator
import groovyx.net.http.Method
import org.apache.commons.io.IOUtils
import org.restapidoc.annotation.*
import org.restapidoc.pojo.RestApiParamType
import org.springframework.web.multipart.support.AbstractMultipartHttpServletRequest

import static org.springframework.security.acls.domain.BasePermission.DELETE
import static org.springframework.security.acls.domain.BasePermission.READ
import static org.springframework.security.acls.domain.BasePermission.WRITE
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.apache.commons.codec.binary.Base64;
import org.springframework.web.client.RestTemplate
import org.springframework.web.client.HttpClientErrorException

/**
 * Controller for a description (big text data/with html format) on a specific domain
 */
@RestApi(name = "Utils | attached services", description = "Methods for managing snapshot file on a specific domain")
class RestSnapshotFileController extends RestController {

    def springSecurityService
    def securityACLService
    def cytomineService
    def snapshotFileService
    def configurationService
    def imageInstanceService
    def imageRetrievalService
    def simplifyGeometryService

    @RestApiMethod(description="List all snapshot file available", listing=true)
    def list() {
        securityACLService.checkAdmin(cytomineService.currentUser)
        responseSuccess(snapshotFileService.list())
    }
    @RestApiMethod(description="Send webhook")
    def webhook() {
        def jsonBody = new JsonSlurper().parseText(request.reader.text)
        def url = jsonBody.sendUrl
        jsonBody.remove('sendUrl')
        HttpHeaders headers = new HttpHeaders()
        headers.setContentType(MediaType.APPLICATION_JSON);
        Configuration username = null;
        Configuration password = null;
        try {
            username = configurationService.readByKey('WEBHOOK_USERNAME')
            password = configurationService.readByKey('WEBHOOK_PASSWORD')
        } catch (ignored) {

        }
        if(username){
            String auth = username.value+":"+password.value
            byte[] encodedAuth = Base64.encodeBase64(auth.getBytes("UTF-8"))
            String authHeader = "Basic " + new String(encodedAuth);
            headers.set("Authorization", authHeader);
        }
        HttpEntity<String> entity = new HttpEntity<String>(jsonBody, headers)
        RestTemplate restTemplate = new RestTemplate()
        try {
            String response = restTemplate.postForObject(url, entity, String.class)
            String jsonString = """
                {
                    "webhookURL": "${url.toString()}",
                    "response": ${response},               
                }
                """
            def json = grails.converters.JSON.parse(jsonString)
            responseSuccess(json)
        } catch (HttpClientErrorException e) {
            responseError(new WrongArgumentException(e.getResponseBodyAsString()))
        }

    }
    @RestApiMethod(description="Get the snapshot from the image by location")
    def getSnapshot() {
        def jsonBody = new JsonSlurper().parseText(request.reader.text)
        SliceInstance slice = SliceInstance.read(jsonBody.slice)

        def uri = "/image/" + slice.baseSlice.uploadedFile.filename +"/annotation/crop"
        def server = grailsApplication.config.grails.imageServerURL[0]
        def geometry = new WKTReader().read(jsonBody.location as String)
        def wkt = simplifyGeometryService.simplifyPolygonForCrop(geometry).toText()
        def parameters = [
                length: 512,
                annotations: [geometry: wkt],
                z_slices: 0,
                timepoints: 0,
                background_transparency: 0
        ]
        def headers = ['X-Annotation-Origin': 'LEFT_BOTTOM']
        def request = makeRequest(uri, server, parameters, 'image/jpeg', headers)
        def result= snapshotFileService.add(jsonBody.imageName,request.content,null,jsonBody.image,jsonBody.imageClass)
        responseSuccess(result)
    }

    @RestApiMethod(description="List all snapshot file for a given domain", listing=true)
    @RestApiParams(params=[
        @RestApiParam(name="domainIdent", type="long", paramType = RestApiParamType.PATH, description = "The domain id"),
        @RestApiParam(name="domainClassName", type="string", paramType = RestApiParamType.PATH, description = "The domain class")
    ])
    def listByDomain() {
        Long domainIdent = params.long("domainIdent")
        String domainClassName = params.get("domainClassName")
        if(domainClassName.contains("AbstractImage")) {
            securityACLService.checkAtLeastOne(domainIdent,domainClassName,"containers",READ)
        } else if(domainClassName.contains("AnnotationDomain")) {
            AnnotationDomain annotation = AnnotationDomain.getAnnotationDomain(domainIdent)
            securityACLService.check(domainIdent,annotation.getClass().name,"container",READ)
        } else {
            securityACLService.check(domainIdent,domainClassName,"container",READ)
        }
        responseSuccess(snapshotFileService.list(domainIdent,domainClassName))
    }

    @RestApiMethod(description="Get a specific snapshot file")
    @RestApiParams(params=[
        @RestApiParam(name="id", type="long", paramType = RestApiParamType.PATH, description = "The snapshot file id")
    ])
    def show() {
        SnapshotFile file = snapshotFileService.read(params.get('id'))
        if(file) {
            if(file.domainClassName.contains("AbstractImage")) {
                securityACLService.checkAtLeastOne(file.domainIdent, file.domainClassName, "containers", READ)
            } else {
                securityACLService.check(file.domainIdent,file.domainClassName,"container",READ)
            }
            responseSuccess(file)
        } else {
            responseNotFound("SnapshotFile",params.get('id'))
        }

    }

    @RestApiMethod(description="Download a file for a given snapshot file")
    @RestApiParams(params=[
        @RestApiParam(name="id", type="long", paramType = RestApiParamType.PATH, description = "The snapshot file id")
    ])
    @RestApiResponseObject(objectIdentifier = "file")
    def download() {
        SnapshotFile attached = snapshotFileService.read(params.get('id'))
        if(!attached) {
            responseNotFound("SnapshotFile",params.get('id'))
        } else {
            responseFile(attached.filename, attached.data)
        }
    }

    @RestApiMethod(description="Upload a file for a domain")
    @RestApiParams(params=[
        @RestApiParam(name="domainIdent", type="long", paramType = RestApiParamType.PATH, description = "The domain id"),
        @RestApiParam(name="domainClassName", type="string", paramType = RestApiParamType.PATH, description = "The domain class")
    ])
    def upload() {
        log.info "Upload snapshot file"
        Long domainIdent = params.long("domainIdent")
        String domainClassName = params.get("domainClassName")
        String key = params.get("key")

        if(request instanceof AbstractMultipartHttpServletRequest) {
            def f = ((AbstractMultipartHttpServletRequest) request).getFile('files[]')

            if(domainClassName == null) domainClassName = ((AbstractMultipartHttpServletRequest) request).getParameter('domainClassName')
            if(domainIdent == null) domainIdent = Long.parseLong(((AbstractMultipartHttpServletRequest) request).getParameter('domainIdent'))

            String filename = ((AbstractMultipartHttpServletRequest) request).getParameter('filename')
            if(!filename) filename = f.originalFilename

            log.info "Upload $filename for domain $domainClassName $domainIdent"
            log.info "File size = ${f.size}"

            CytomineDomain recipientDomain = Class.forName(domainClassName, false, Thread.currentThread().contextClassLoader).read(domainIdent)
            if(recipientDomain instanceof AbstractImage) {
                securityACLService.checkAtLeastOne(domainIdent, domainClassName, "containers", READ)
            } else if(recipientDomain instanceof Project || !recipientDomain.container() instanceof Project) {
                securityACLService.check(domainIdent,domainClassName,"container",WRITE)
            } else {
                securityACLService.checkFullOrRestrictedForOwner(domainIdent,domainClassName, "user")
            }
            def result = snapshotFileService.add(filename,f.getBytes(),key,domainIdent,domainClassName)
            responseSuccess(result)
        } else {
            responseError(new WrongArgumentException("No snapshot File attached"))
        }
    }

    @RestApiMethod(description="Upload a file for a domain. Decode params filled by RTEditor")
    @RestApiParams(params=[
    @RestApiParam(name="domainIdent", type="long", paramType = RestApiParamType.PATH, description = "The domain id"),
    @RestApiParam(name="domainClassName", type="string", paramType = RestApiParamType.PATH, description = "The domain class")
    ])
    def uploadFromRTEditor() {
        log.info "Upload snapshot file"
        Long domainIdent = params.long("domainIdent")
        String domainClassName = params.get("domainClassName")
        String key = params.get("key")
        def upload = params.image
        String filename = upload.getOriginalFilename()
        log.info "Upload $filename for domain $domainClassName $domainIdent"

        CytomineDomain recipientDomain = Class.forName(domainClassName, false, Thread.currentThread().contextClassLoader).read(domainIdent)
        if(recipientDomain instanceof AbstractImage) {
            securityACLService.checkAtLeastOne(domainIdent, domainClassName, "containers", READ)
        } else if(recipientDomain instanceof Project || !recipientDomain.container() instanceof Project) {
            securityACLService.check(domainIdent,domainClassName,"container",WRITE)
        } else {
            securityACLService.checkFullOrRestrictedForOwner(domainIdent,domainClassName)
        }
        def result = snapshotFileService.add(filename,upload.getBytes(),key,domainIdent,domainClassName)

        responseSuccess(result)

    }

    @RestApiMethod(description="Delete an snapshot file")
    @RestApiParams(params=[
            @RestApiParam(name="id", type="long", paramType = RestApiParamType.PATH,description = "The snapshot file id")
    ])
    def delete() {
        SnapshotFile domain = snapshotFileService.read(params.id)
        CytomineDomain recipientDomain = domain.retrieveCytomineDomain()
        if(recipientDomain instanceof AbstractImage) {
            securityACLService.checkAtLeastOne(domain.domainIdent, domain.domainClassName, "containers", READ)
        } else if(recipientDomain instanceof Project || !recipientDomain.container() instanceof Project) {
            securityACLService.check(domain.domainIdent,domain.domainClassName,"container",DELETE)
        } else {
            securityACLService.checkFullOrRestrictedForOwner(domain.domainIdent,domain.domainClassName, "user")
        }

        delete(snapshotFileService, JSON.parse("{id : $params.id}"),null)
    }
    private static def makeRequest(def path, def server, def parameters,
                                   def format, def  customHeaders=[:]) {
        parameters = filterParameters(parameters)
        def url = makeGetUrl(path, server, parameters)
        def responseContentType = format
        def okClosure = { resp, stream ->
            return new ImageResponse(IOUtils.toByteArray(stream), extractPIMSHeaders(resp.headers))
        }
        def notModifiedClosure = { resp ->
            throw new NotModifiedException(extractPIMSHeaders(resp.headers))
        }
        def badRequestClosure = { resp, json ->
            log.error(json)
            throw new InvalidRequestException("$url returned a 400 Bad Request")
        }
        def notFoundClosure = { resp ->
            log.error(resp)
            throw new ObjectNotFoundException("$url returned a 404 Not found")
        }
        def internalServerErrorClosure = { resp ->
            log.error(resp)
            throw new ServerException("$url returned a 500 Internal error")
        }
        def http = new HTTPBuilder(server)

        http.request(Method.POST, responseContentType) {
            uri.path = path
            requestContentType = ContentType.JSON
            body = JsonOutput.toJson(parameters)
            headers = customHeaders

            response.'200' = okClosure
            response.'304' = notModifiedClosure
            response.'400' = badRequestClosure
            response.'404' = notFoundClosure
            response.'422' = badRequestClosure
            response.'500' = internalServerErrorClosure
        }
    }
    private static def extractPIMSHeaders(HttpResponseDecorator.HeadersDecorator headers) {
        def names = ["Cache-Control", "ETag", "X-Annotation-Origin", "X-Image-Size-Limit"]
        def extractedHeaders = [:]
        names.each { name ->
            def h = headers[name] ?: headers[name.toLowerCase()]
            if (h) {
                extractedHeaders << [(name): h.getValue()]
            }
        }
        return extractedHeaders
    }
    private static def makeGetUrl(def uri, def server, def parameters) {
        parameters = filterParameters(parameters)
        String query = parameters.collect { key, value ->
            if (value instanceof List)
                value = value.join(',')

            if (value instanceof Geometry)
                value = value.toText()

            if (value instanceof String)
                value = URLEncoder.encode(value, "UTF-8")
            "$key=$value"
        }.join("&")

        return "$server$uri?$query"
    }

    private static def filterParameters(parameters) {
        parameters.findAll { it.value != null && it.value != ""}
    }
}


