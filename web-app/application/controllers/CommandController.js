var CommandController = Backbone.Controller.extend({
    undo : function() {
        var self = this;
        $.post('command/undo.json', {}, function(data) {
            console.log("data:");
            console.log(data);
            _.each(data, function(undoElem){
                console.log("undoElem" + undoElem);
                console.log(undoElem);
                self.dispatch(undoElem.callback,undoElem.message,"Undo");
                console.log("PRINT MESSAGE:"+undoElem.printMessage);
                if(undoElem.printMessage) {
                    console.log("********PRINT*******");
                    window.app.view.message("Undo", undoElem.message, "");
                }
            });

        }, "json");

    },

    redo : function () {
        var self = this;
        $.post('command/redo.json', {}, function(data) {
            console.log("data:");
            console.log(data);
            _.each(data, function(redoElem){
                console.log("redoElem" + redoElem);
                self.dispatch(redoElem.callback,redoElem.message, "Redo");
                if(redoElem.printMessage) window.app.view.message("Redo", redoElem.message, "");
            });
        }, "json");

    },

    dispatch : function(callback,message,operation) {
        console.log(callback);

        if (!callback) return; //nothing to do
        console.log("callback method ? " + callback.method);
        /**
         * ANNOTATION
         */
        if (callback.method == "be.cytomine.AddAnnotationCommand") {

            var tab = _.detect(window.app.controllers.browse.tabs.tabs, function(object) {
                console.log("object.idImage="+object.idImage + " callback.imageID=" + callback.imageID);
                return object.idImage == callback.imageID;
            });
            var image = tab.view;
            console.log(tab);
            if (image == undefined) return; //tab is closed
            console.log("callback.annotationID="+callback.annotationID);
            image.getUserLayer().annotationAdded(callback.annotationID);
            if(window.app.controllers.dashboard.view!=null)
                window.app.controllers.dashboard.view.refresh();
        } else if (callback.method == "be.cytomine.EditAnnotationCommand") {

            var tab = _.detect(window.app.controllers.browse.tabs.tabs, function(object) {
                return object.idImage == callback.imageID;
            });
            var image = tab.view;
            if (image == undefined) return; //tab is closed
            image.getUserLayer().annotationUpdated(callback.annotationID);
            if(window.app.controllers.dashboard.view!=null)
                window.app.controllers.dashboard.view.refresh();
        } else if (callback.method == "be.cytomine.DeleteAnnotationCommand") {

            var tab = _.detect(window.app.controllers.browse.tabs.tabs, function(object) {
                return object.idImage == callback.imageID;
            });
            var image = tab.view;
            console.log(tab);
            console.log("tab.view="+tab.view);
            if (image == undefined) return; //tab is closed
            console.log("callback.annotationID="+callback.annotationID);
            image.getUserLayer().annotationRemoved(callback.annotationID);
              if(window.app.controllers.dashboard.view!=null)
                window.app.controllers.dashboard.view.refresh();
            /**
             * ANNOTATION TERM
             */
        } else if (callback.method == "be.cytomine.AddAnnotationTermCommand") {

            var tab = _.detect(window.app.controllers.browse.tabs.tabs, function(object) {
                return object.idImage == callback.imageID;
            });
            var image = tab.view;
            if (image == undefined) return; //tab is closed
            image.getUserLayer().termAdded(callback.annotationID,callback.termID);
            if(window.app.controllers.dashboard.view!=null)
                window.app.controllers.dashboard.view.refresh();
        } else if (callback.method == "be.cytomine.DeleteAnnotationTermCommand") {

            var tab = _.detect(window.app.controllers.browse.tabs.tabs, function(object) {
                return object.idImage == callback.imageID;
            });
            var image = tab.view;
            if (image == undefined) return; //tab is closed
            image.getUserLayer().termRemoved(callback.annotationID,callback.termID);
            if(window.app.controllers.dashboard.view!=null)
                window.app.controllers.dashboard.view.refresh();
        }

        /**
         * ONTOLOGY
         */
        else if (callback.method == "be.cytomine.AddOntologyCommand") {

            window.app.controllers.ontology.view.refresh(callback.ontologyID);
        } else if (callback.method == "be.cytomine.DeleteOntologyCommand") {

            window.app.controllers.ontology.view.refresh();
        } else if (callback.method == "be.cytomine.EditOntologyCommand") {

            window.app.controllers.ontology.view.refresh(callback.ontologyID);
        }
        /**
         * PROJECT
         */
        else if (callback.method == "be.cytomine.AddProjectCommand") {

            window.app.controllers.project.view.refresh();
        } else if (callback.method == "be.cytomine.DeleteProjectCommand") {

            window.app.controllers.project.view.refresh();
        } else if (callback.method == "be.cytomine.EditProjectCommand") {

            window.app.controllers.project.view.refresh();
        }
        /**
         * TERM
         */
        else if (callback.method == "be.cytomine.AddTermCommand") {

            window.app.controllers.ontology.view.refresh(callback.ontologyID);
        } else if (callback.method == "be.cytomine.DeleteTermCommand") {

            window.app.controllers.ontology.view.refresh(callback.ontologyID);
        } else if (callback.method == "be.cytomine.EditTermCommand") {

            window.app.controllers.ontology.view.refresh(callback.ontologyID);
        }

        else if (callback.method == "be.cytomine.AddImageInstanceCommand") {
            if(window.app.controllers.project.view!=null)
                window.app.controllers.project.view.refresh();
            if(window.app.controllers.dashboard.view!=null)
                window.app.controllers.dashboard.view.refresh();
        } else if (callback.method == "be.cytomine.DeleteImageInstanceCommand") {
            console.log("be.cytomine.DeleteImageInstanceCommand");
            if(window.app.controllers.project.view!=null)
                window.app.controllers.project.view.refresh();
            if(window.app.controllers.dashboard.view!=null)
                window.app.controllers.dashboard.view.refresh();
        } else if (callback.method == "be.cytomine.EditImageInstanceCommand") {
            if(window.app.controllers.project.view!=null)
                window.app.controllers.project.view.refresh();
            if(window.app.controllers.dashboard.view!=null)
                window.app.controllers.dashboard.view.refresh();
        }

    }
});