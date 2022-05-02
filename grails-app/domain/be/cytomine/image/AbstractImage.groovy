package be.cytomine.image

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
import be.cytomine.Exception.CytomineException
import be.cytomine.api.UrlApi
import be.cytomine.image.acquisition.Instrument
import be.cytomine.laboratory.Sample
import be.cytomine.security.SecUser
import be.cytomine.utils.JSONUtils
import org.restapidoc.annotation.RestApiObject
import org.restapidoc.annotation.RestApiObjectField
import org.restapidoc.annotation.RestApiObjectFields

@RestApiObject(name = "Abstract image", description = "A N-dimensional image stored on disk")
class AbstractImage extends CytomineDomain implements Serializable {

    @RestApiObjectField(description = "The underlying file stored on disk")
    UploadedFile uploadedFile

    @RestApiObjectField(description = "The image filename (will be show in GUI)", useForCreation = false)
    String originalFilename

    // TODO: REMOVE ?
    @RestApiObjectField(description = "The instrument that digitalize the image", mandatory = false)
    Instrument scanner

    // TODO: REMOVE ?
    @RestApiObjectField(description = "The source of the image (human, annimal,...)", mandatory = false)
    Sample sample

    @RestApiObjectField(description = "The N-dimensional image width, in pixels (X)", mandatory = false, defaultValue = "-1")
    Integer width

    @RestApiObjectField(description = "The N-dimensional image height, in pixels (Y)", mandatory = false, defaultValue = "-1")
    Integer height

    @RestApiObjectField(description = "The N-dimensional image depth, in z-slices (Z)", mandatory = false, defaultValue = "1")
    Integer depth

    @RestApiObjectField(description = "The N-dimensional image duration, in frames (T)", mandatory = false, defaultValue = "1")
    Integer duration

    @RestApiObjectField(description = "The N-dimensional image channels (C)", mandatory = false, defaultValue = "1")
    Integer channels // [PIMS] Concrete number of channels (RGB image = 1 concrete channel / 3 samples)
    // TODO: in a new API, should be renamed

    @RestApiObjectField(description = "The number of samples per pixel", defaultValue = "8")
    Integer samplePerPixel = 8

    @RestApiObjectField(description = "The number of bits used to encode a sample")
    Integer bitPerSample

    @RestApiObjectField(description = "Physical size of a pixel along X axis", mandatory = false)
    Double physicalSizeX

    @RestApiObjectField(description = "Physical size of a pixel along Y axis", mandatory = false)
    Double physicalSizeY

    @RestApiObjectField(description = "Physical size of a pixel along Z axis", mandatory = false)
    Double physicalSizeZ

    @RestApiObjectField(description = "The number of frames per second", mandatory = false)
    Double fps

    @RestApiObjectField(description = "The image max zoom")
    Integer magnification

    // TODO: Remove, no more filled by [PIMS]
    @RestApiObjectField(description = "The image colorspace")
    String colorspace

    @RestApiObjectField(description = "The image owner", mandatory = false, defaultValue = "current user")
    SecUser user //owner

    static belongsTo = Sample

    @RestApiObjectFields(params=[
        @RestApiObjectField(apiFieldName = "metadataUrl", description = "URL to get image file metadata",allowedType = "string",useForCreation = false),
        @RestApiObjectField(apiFieldName = "thumb", description = "URL to get abstract image short view (htumb)",allowedType = "string",useForCreation = false),
        @RestApiObjectField(apiFieldName = "filename", description = "Similar to original filename.", allowedType = "string", useForCreation = false),
        @RestApiObjectField(apiFieldName = "path", description = "The internal path of the file", allowedType = "string", useForCreation = false),
        @RestApiObjectField(apiFieldName = "dimensions", description = "Textual dimensions of the image: XY, XYZ, XYC, XYT, XYZC, XYZT, XYCT, XYCZT", allowedType = "string", useForCreation = false),
        @RestApiObjectField(apiFieldName = "contentType", description = "The image content type", allowedType = "string", useForCreation = false),
        @RestApiObjectField(apiFieldName = "zoom", description = "The number of zooms available in the image", allowedType = "int", useForCreation = false),
        @RestApiObjectField(apiFieldName = "preview", description = "URL to get image preview", allowedType = "string", useForCreation = false),
        @RestApiObjectField(apiFieldName = "macroURL", description = "URL to get image macros", allowedType = "string", useForCreation = false),

    ])

    static mapping = {
        id generator: "assigned"
        sort "id"
        cache(true)
        physicalSizeX column: "physical_size_x"
        physicalSizeY column: "physical_size_y"
        physicalSizeZ column: "physical_size_z"
        uploadedFile fetch: 'join'
        sample fetch: 'join', cache: true
    }

    static constraints = {
        uploadedFile(nullable: true) // shouldn't be nullable
        originalFilename(nullable: true, blank: false, unique: false)
        scanner(nullable: true)
        sample(nullable: true)
        width(nullable: true, min: 1)
        height(nullable: true, min: 1)
        depth(nullable: true, min: 1)
        duration(nullable: true, min: 1)
        channels(nullable: true, min: 1)
        physicalSizeX(nullable: true)
        physicalSizeY(nullable: true)
        physicalSizeZ(nullable: true)
        fps(nullable: true)
        magnification(nullable: true)
        bitPerSample(nullable: true)
        colorspace(nullable: true)
        user(nullable: true)
        samplePerPixel(nullable: true)
    }

    /**
     * Insert JSON data into domain in param
     * @param domain Domain that must be filled
     * @param json JSON containing data
     * @return Domain with json data filled
     * @throws CytomineException Error during properties copy (wrong argument,...)
     */
    static AbstractImage insertDataIntoDomain(def json,def domain = new AbstractImage()) throws CytomineException {
        domain.id = JSONUtils.getJSONAttrLong(json,'id',null)
        domain.created = JSONUtils.getJSONAttrDate(json,'created')
        domain.updated = JSONUtils.getJSONAttrDate(json,'updated')
        domain.deleted = JSONUtils.getJSONAttrDate(json, "deleted")

        domain.originalFilename = JSONUtils.getJSONAttrStr(json,'originalFilename')

        domain.uploadedFile = JSONUtils.getJSONAttrDomain(json, "uploadedFile", new UploadedFile(), true)

        domain.height = JSONUtils.getJSONAttrInteger(json,'height',null)
        domain.width = JSONUtils.getJSONAttrInteger(json,'width',null)
        domain.depth = JSONUtils.getJSONAttrInteger(json, "depth", 1)
        domain.duration = JSONUtils.getJSONAttrInteger(json, "duration", 1)
        domain.channels = JSONUtils.getJSONAttrInteger(json, "channels", 1)
        domain.samplePerPixel = JSONUtils.getJSONAttrInteger(json, 'samplePerPixel', 1)
        domain.bitPerSample = JSONUtils.getJSONAttrInteger(json, 'bitPerSample', 8)

        domain.physicalSizeX = JSONUtils.getJSONAttrDouble(json, "physicalSizeX", null)
        domain.physicalSizeY = JSONUtils.getJSONAttrDouble(json, "physicalSizeY", null)
        domain.physicalSizeZ = JSONUtils.getJSONAttrDouble(json, "physicalSizeZ", null)
        domain.fps = JSONUtils.getJSONAttrDouble(json, "fps", null)

        domain.scanner = JSONUtils.getJSONAttrDomain(json,"scanner",new Instrument(),false)
        domain.sample = JSONUtils.getJSONAttrDomain(json,"sample",new Sample(),false)
        domain.magnification = JSONUtils.getJSONAttrInteger(json,'magnification',null)

        domain.colorspace = JSONUtils.getJSONAttrStr(json, 'colorspace', false)
        return domain;
    }

    /**
     * Define fields available for JSON response
     * @param domain Domain source for json value
     * @return Map with fields (keys) and their values
     */
    static def getDataFromDomain(AbstractImage image) {
        def returnArray = CytomineDomain.getDataFromDomain(image)
        returnArray['filename'] = image?.filename
        returnArray['originalFilename'] = image?.originalFilename
        returnArray['scanner'] = image?.scanner?.id
        returnArray['sample'] = image?.sample?.id
        returnArray['uploadedFile'] = image?.uploadedFile?.id
        returnArray['path'] = image?.path
        returnArray['contentType'] = image?.uploadedFile?.contentType
        returnArray['width'] = image?.width
        returnArray['height'] = image?.height
        returnArray['depth'] = image?.depth // /!!\ Breaking API : image?.getZoomLevels()?.max
        returnArray['duration'] = image?.duration
        returnArray['channels'] = image?.channels
        returnArray['dimensions'] = image?.dimensions
        returnArray['apparentChannels'] = image?.apparentChannels

        returnArray['physicalSizeX'] = image?.physicalSizeX
        returnArray['physicalSizeY'] = image?.physicalSizeY
        returnArray['physicalSizeZ'] = image?.physicalSizeZ
        returnArray['fps'] = image?.fps

        returnArray['zoom'] = image?.getZoomLevels()

        returnArray['magnification'] = image?.magnification
        returnArray['bitPerSample'] = image?.bitPerSample
        returnArray['samplePerPixel'] = image?.samplePerPixel
        returnArray['colorspace'] = image?.colorspace
        returnArray['thumb'] = UrlApi.getAbstractImageThumbUrlWithMaxSize(image ? (long)image?.id : null, 512)
        returnArray['preview'] = UrlApi.getAbstractImageThumbUrlWithMaxSize(image ? (long)image?.id : null, 1024)
        returnArray['macroURL'] = UrlApi.getAssociatedImage(image, "macro", image?.uploadedFile?.contentType, 256)
        returnArray
    }

    def getApparentChannels() {
        return channels * samplePerPixel
    }

    def getPath() {
        return uploadedFile?.path
    }

    def getSliceCoordinates() {
        def slices = AbstractSlice.findAllByImage(this)

        return [
                channels: slices.collect { it.channel }.unique().sort(),
                zStacks: slices.collect { it.zStack }.unique().sort(),
                times: slices.collect { it.time }.unique().sort()
        ]
    }

    def getReferenceSliceCoordinate() {
        return [
                channel: (int) Math.floor(this.channels / 2),
                zStack: (int) Math.floor(this.depth / 2),
                time: (int) Math.floor(this.duration / 2),
        ]
    }

    def getReferenceSlice() {
        def coord = getReferenceSliceCoordinate()
        return AbstractSlice.findByImageAndChannelAndZStackAndTime(this, coord.channel, coord.zStack, coord.time)
    }

    def getImageServerUrl() {
        return uploadedFile?.imageServer?.url
    }

    def getImageServerInternalUrl() {
        return uploadedFile?.imageServer?.internalUrl
    }

    def getZoomLevels() {
        if (!width || !height)
            return 1

        double tmpWidth = width
        double tmpHeight = height
        def nbZoom = 0
        while (tmpWidth > 256 || tmpHeight > 256) {
            nbZoom++
            tmpWidth /= 2
            tmpHeight /= 2
        }

        return nbZoom
    }

    def getFilename() {
        return originalFilename
    }

    def getDimensions() {
        def dimensions = ['X', 'Y']
        if (channels > 1) dimensions << 'C'
        if (depth > 1) dimensions << 'Z'
        if (duration > 1) dimensions << 'T'
        return dimensions.join()
    }

    def hasProfile() {
        return CompanionFile.countByImageAndType(this, "HDF5") as Boolean
    }

    /**
     * Get the container domain for this domain (usefull for security)
     * @return Container of this domain
     */
    public CytomineDomain container() {
        uploadedFile.container()
    }
}