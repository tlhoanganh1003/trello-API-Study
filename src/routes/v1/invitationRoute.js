/**
* YouTube: https://youtube.com/@trungquandev
* "A bit of fragrance clings to the hand that gives flowers!"
*/
import express from 'express'
import { invitationValidation } from '~/validations/invitationValidation'
import { invitationController } from '~/controllers/invitationController'
import { authMiddleware } from '~/middlewares/authMiddleware'


const Router = express.Router()


Router.route('/board')
  .post(authMiddleware.isAuthorized,
    invitationValidation.createNewBoardInvitation,
    invitationController.createNewBoardInvitation
  )
// Get invitations by User
Router.route('/')
  .get(authMiddleware.isAuthorized, invitationController.getInvitations)


export const invitationRoute = Router


