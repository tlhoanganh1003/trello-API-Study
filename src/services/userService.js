import { userModel } from '~/models/userModel'
import ApiError from '~/utils/ApiError'
import { StatusCodes } from 'http-status-codes'
import bcryptjs from 'bcryptjs'
import { v4 as uuidv4 } from 'uuid'
import { pickUser } from '~/utils/formatters'
const createNew = async (reqBody) => {
  try {

    const existUser = await userModel.findOneByEmail(reqBody.email)

    if (existUser) {
      throw new ApiError(StatusCodes.CONFLICT, 'Email already exists!')
    }
    // nameFromEmail: ví dụ nếu email là trungquandev@gmail.com thì sẽ lấy được "trungquandev"
    const nameFromEmail = reqBody.email.split('@')[0]
    const newUser = {
      email: reqBody.email,
      password: bcryptjs.hashSync(reqBody.password, 8),
      username: nameFromEmail,
      //mặc định giống username
      displayName: nameFromEmail,
      verifyToken: uuidv4()
    }

    //thực hiện lưu thông tin user vào DaTaBase
    const createdUser = await userModel.createNew(newUser)
    const getNewUser = await userModel.findOneById(createdUser.insertedId)
    //gửi email cho người dùng xác thực tài khoản


    //return trả về dữ liệu cho controller
    return pickUser(getNewUser)

  } catch (error) { throw error }
}
export const userService = {
  createNew
}
