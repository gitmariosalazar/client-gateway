import { ApiProperty } from "@nestjs/swagger";

export class SignInRequest {

  @ApiProperty({
    description: 'The email address of the user',
    example: 'mariosalazar.ms.10@gmail.com',
    required: true,
    type: String,
    format: 'email',
  })
  email: string;

  @ApiProperty({
    description: 'The password of the user',
    example: 'password123',
    required: true,
    type: String,
    format: 'password',
  })
  password: string;

  constructor(email: string, password: string) {
    this.email = email;
    this.password = password;
  }
}