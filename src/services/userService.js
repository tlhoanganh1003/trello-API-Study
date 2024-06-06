import { userModel } from '~/models/userModel'
import ApiError from '~/utils/ApiError'
import { StatusCodes } from 'http-status-codes'
import bcryptjs from 'bcryptjs'
import { v4 as uuidv4 } from 'uuid'
import { pickUser } from '~/utils/formatters'
import { WEBSITE_DOMAIN } from '~/utils/constants'
import { BrevoProvider } from '~/providers/BrevoProvider'
import { JwtProvider } from '~/providers/JwtProvider'
import { env } from '~/config/environment'

const createNew = async (reqBody) => {
  try {
    // Kiểm tra xem email người dùng gửi lên đã tồn tại trong hệ thống của chúng ta hay chưa
    const existUser = await userModel.findOneByEmail(reqBody.email)
    if (existUser) {
      throw new ApiError(StatusCodes.CONFLICT, 'Email already exists!')
    }

    // Tạo data để lưu vào Database
    // nameFromEmail: ví dụ nếu email là trungquandev@gmail.com thì sẽ lấy được "trungquandev"
    const nameFromEmail = reqBody.email.split('@')[0]
    const newUser = {
      email: reqBody.email,
      // tham số thứ 2 của hàm hashSync là độ phức tạp, giá trị càng lớn thì thời gian hash password càng lâu
      password: bcryptjs.hashSync(reqBody.password, 8),
      username: nameFromEmail,
      // Mặc định để giống username, về sau sẽ làm tính năng cho user cập nhật thông tin của họ.
      displayName: nameFromEmail,
      verifyToken: uuidv4()
    }
    // Thực hiện lưu thông tin user vào DB
    const createdUser = await userModel.createNew(newUser)
    const getNewUser = await userModel.findOneById(createdUser.insertedId)

    // Gửi email cho người dùng xác thực tài khoản của họ
    const verificationLink = `${WEBSITE_DOMAIN}/account/verification?email=${getNewUser.email}&token=${getNewUser.verifyToken}`
    const customSubject = 'Trello MERN Stack Advanced: Please verify your email before using our services!'
    const customHtmlContent = `
      <h3>Here is your verification link:</h3>
      <h3>${verificationLink}</h3>
      <h3>Sincerely,<br/> - Trungquandev - Một Lập Trình Viên - </h3>
    `
    // Gọi tới BrevoProvider để gửi email
    await BrevoProvider.sendEmail(getNewUser.email, customSubject, customHtmlContent)

    // Return trả về dữ liệu cho phía Controller
    return pickUser(getNewUser)
  } catch (error) { throw error }
}

const verifyAccount = async (reqBody) => {
  try {
    // Kiểm tra xem email người dùng gửi lên đã tồn tại trong hệ thống của chúng ta hay chưa
    const existUser = await userModel.findOneByEmail(reqBody.email)
    if (!existUser) {
      throw new ApiError(StatusCodes.NOT_FOUND, 'Account not found!')
    }

    // Kiểm tra xem tài khoản đã active hay chưa
    if (existUser.isActive) {
      throw new ApiError(StatusCodes.NOT_ACCEPTABLE, 'Your account is already active!')
    }

    // Kiểm tra xem token người dùng đẩy lên có đúng hay không
    if (reqBody.token !== existUser.verifyToken) {
      throw new ApiError(StatusCodes.NOT_ACCEPTABLE, 'Token is invalid.')
    }

    // Nếu như mọi thứ ok thì cập nhật thông tin user
    const updateData = {
      isActive: true,
      verifyToken: null
    }

    const updatedUser = await userModel.update(existUser._id, updateData)

    return pickUser(updatedUser)
  } catch (error) { throw error }
}

const login = async (reqBody) => {
  try {
    // Query user trong Database
    const existUser = await userModel.findOneByEmail(reqBody.email)
    // Các bước kiểm tra cần thiết
    if (!existUser) throw new ApiError(StatusCodes.NOT_FOUND, 'Account not found!')
    if (!existUser.isActive) throw new ApiError(StatusCodes.NOT_ACCEPTABLE, 'Your account is not active!')

    // Bước kiểm tra password
    if (!bcryptjs.compareSync(reqBody.password, existUser.password)) {
      throw new ApiError(StatusCodes.NOT_ACCEPTABLE, 'Your email or password is incorrect!')
    }

    /** Nếu mọi thứ ok thì bắt đầu tạo Tokens để trả về cho phía FE */

    // Tạo thông tin để đính kèm trong JWT Token: bao gồm _id và email của user
    const userInfo = { _id: existUser._id, email: existUser.email }

    // Tạo ra 2 loại token, accessToken và refreshToken để trả về cho phía Front-end
    const accessToken = await JwtProvider.generateToken(
      userInfo,
      env.ACCESS_TOKEN_SECRET_SIGNATURE,
      //5// 5 giây
      env.ACCESS_TOKEN_LIFE
    )
    const refreshToken = await JwtProvider.generateToken(
      userInfo,
      env.REFRESH_TOKEN_SECRET_SIGNATURE,
      env.REFRESH_TOKEN_LIFE
    )

    // Trả về thông tin của user kèm theo 2 cái token vừa tạo ra
    return {
      ...pickUser(existUser),
      accessToken,
      refreshToken
    }
  } catch (error) { throw error }
}

export const userService = {
  createNew,
  verifyAccount,
  login
}