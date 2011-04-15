package be.cytomine.command.project

import be.cytomine.command.Command
import be.cytomine.command.UndoRedoCommand
import be.cytomine.project.Project
import grails.converters.JSON
import be.cytomine.command.DeleteCommand

class DeleteProjectCommand extends DeleteCommand implements UndoRedoCommand {

  def execute() {
    def postData = JSON.parse(postData)

    Project project = Project.findById(postData.id)
    data = project.encodeAsJSON()

    if (!project) {
      return [data : [success : false, message : "Project not found with id: " + postData.id], status : 404]
    }
    try {
      project.delete(flush:true);
      return [data : [success : true, message : "OK", data : [project : postData.id]], status : 200]
    } catch(org.springframework.dao.DataIntegrityViolationException e)
    {
      log.error(e)
      return [data : [success : false, errors : "Project is still map with data"], status : 400]
    }
  }

  def undo() {
    def projectData = JSON.parse(data)
    Project project = Project.createProjectFromData(projectData)
    project.save(flush:true)

    //save new id of the object that has been re-created
    def postDataLocal = JSON.parse(postData)
    postDataLocal.id =  project.id
    postData = postDataLocal.toString()

    log.debug "image project with id " + project.id

    return [data : [success : true, project : project, message : "OK"], status : 201]
  }

  def redo() {
    def postData = JSON.parse(postData)
    Project project = Project.findById(postData.id)
    project.delete();
    return [data : [success : true, message : "OK"], status : 200]

  }


}
