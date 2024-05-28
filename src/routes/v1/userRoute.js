/**
* TrungQuanDev: https://youtube.com/@trungquandev
* "A bit of fragrance clings to the hand that gives flowers!"
*/
import express from 'express'
import { userValidation } from '~/validations/userValidation'
import { userController } from '~/controllers/userController'


const Router = express.Router()


Router.route('/register')
  .post(userValidation.createNew, userController.createNew)


export const userRoute = Router

