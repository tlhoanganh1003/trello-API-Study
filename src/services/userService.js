import { userModel } from '~/models/userModel'
import ApiError from '~/utils/ApiError'
import { StatusCodes } from 'http-status-codes'
import bcryptjs from 'bcryptjs'
import { v4 as uuidv4 } from 'uuid'
import { pickUser } from '~/utils/formatters'
import { WEBSITE_DOMAIN } from '~/utils/constants'
import { BrevoProvider } from '~/providers/BrevoProvider'

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

export const userService = {
  createNew
}