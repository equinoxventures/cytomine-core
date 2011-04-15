/**
 * Created by IntelliJ IDEA.
 * User: lrollus
 * Date: 7/04/11
 * Time: 10:53
 * To change this template use File | Settings | File Templates.
 */
var TermModel = Backbone.Model.extend({

	url : function() {
		var base = 'api/term';
		var format = '.json';
        if (this.isNew()) return base + format;
		return base + (base.charAt(base.length - 1) == '/' ? '' : '/') + this.id + format;
	}
});

var AnnotationTermModel = Backbone.Model.extend({
	url : function() {
        if (this.term == null)
		    return 'api/annotation/' + this.annotation +'/term.json';
        else
            return 'api/annotation/' + this.annotation +'/term/'+this.term+'.json';
	},
    initialize: function (options) {
        this.annotation = options.annotation;
        this.term = options.term;
    }
});

var AnnotationTermCollection = Backbone.Collection.extend({
    model : TermModel,
	url : function() {
		return 'api/annotation/' + this.idAnnotation +'/term.json';
	},
    initialize: function (options) {
        this.idAnnotation = options.idAnnotation;

    }
});



// define our collection
var TermCollection = Backbone.Collection.extend({
    model: TermModel,
    CLASS_NAME: "be.cytomine.ontology.Term",
    url: 'api/term.json',
    initialize: function () {
        // something
    }
});
