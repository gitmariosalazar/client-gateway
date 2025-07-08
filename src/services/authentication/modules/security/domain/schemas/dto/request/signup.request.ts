import { ApiProperty } from '@nestjs/swagger';

export class SignUpRequest {
  @ApiProperty({
    example: 'mariosalazar.ms.10@gmail.com',
    description: 'User email address',
    uniqueItems: true,
    required: true,
    type: String,
    format: 'email',
  })
  public userEmail: string;
  @ApiProperty({
    example: 'password-mario',
    description: 'Secret key or Password',
    required: true,
    type: String,
    format: 'password',
  })
  public userPassword: string;

  @ApiProperty({
    example: 'password-mario',
    description: 'Confirm Password',
    required: true,
    type: String,
    format: 'password',
  })
  confirmPassword: string;

  @ApiProperty({
    example: 'Mario',
    description: 'First Name to user',
    required: true,
    type: String,
    format: 'text',
  })
  public firstName: string;
  @ApiProperty({
    example: 'Salazar',
    description: 'Last Name to user',
    required: true,
    type: String,
    format: 'text',
  })
  public lastName: string;
}
