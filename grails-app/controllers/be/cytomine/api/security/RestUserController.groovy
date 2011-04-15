package be.cytomine.api.security

import be.cytomine.security.User
import grails.converters.*
import be.cytomine.command.user.AddUserCommand
import be.cytomine.command.UndoStackItem
import be.cytomine.command.Command
import be.cytomine.command.user.EditUserCommand
import be.cytomine.command.user.DeleteUserCommand
import be.cytomine.project.Project
import be.cytomine.api.RestController

/**
 * Handle HTTP Requests for CRUD operations on the User domain class.
 */
class RestUserController extends RestController {

  def springSecurityService
  def transactionService

  /**
   * Render and returns all Users into the specified format given in the request
   * @return all Users into the specified format
   */
  def list = {
    responseSuccess(User.list())
  }

  /**
   * Render and return an User into the specified format given in the request
   * @param id the user identifier
   * @return user an User into the specified format
   */
  def show = {
    User user = User.read(params.id)
    if(user) responseSuccess(user)
    else responseNotFound("User",params.id)
  }

  def showCurrent = {
    responseSuccess(User.read(springSecurityService.principal.id))
  }

  def showByProject = {
    Project project = Project.read(params.id)
    if(project)
      responseSuccess(project.users())
    else responseNotFound("User","Project",params.id)
  }

  /**
   * Create a new User according to the parameters passed into the request.
   * If successful, the new user is rendered and returned into the specified format
   * given in the request. If not, validations errors messages are returned as a response.
   * @param data the data related to the new user
   * @return user the new User into the specified format
   */
  def save = {
    User currentUser = getCurrentUser(springSecurityService.principal.id)
    Command addUserCommand = new AddUserCommand(postData : request.JSON.toString(),user: currentUser)
    def result = processCommand(addUserCommand, currentUser)
    response(result)
  }

  /**
   * Edit an existing User according to the parameters passed into the request.
   * If successful, the user is rendered with its modifications and returned into the specified format
   * given in the request. If not, validations errors messages are returned as a response.
   * @param data the data related to the user
   * @return user the edited User into the specified format
   */
  def update = {
    User currentUser = getCurrentUser(springSecurityService.principal.id)
    Command editUserCommand = new EditUserCommand(postData : request.JSON.toString(),user: currentUser)
    def result = processCommand(editUserCommand, currentUser)
    response(result)
  }

  /**
   * Delete a user according to the identifier passed into the request.
   * @param id the identifier of the user to delete
   * @return the identifier of the deleted user
   */
  def delete =  {
    User currentUser = getCurrentUser(springSecurityService.principal.id)

    def result = null
    if (params.id == springSecurityService.principal.id) {
      result = [data : [success : false, errors : "The user can't delete herself"], status : 403]
      response.status = result.status
    } else {
      def postData = ([id : params.id]) as JSON
      Command deleteUserCommand = new DeleteUserCommand(postData : postData.toString(),user: currentUser)
      result = processCommand(deleteUserCommand, currentUser)
    }
    response(result)
  }
}
