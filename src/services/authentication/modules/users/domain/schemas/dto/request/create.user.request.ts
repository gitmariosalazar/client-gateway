import { ApiProperty } from '@nestjs/swagger';

export class CreateUserRequest {
  @ApiProperty({
    description: 'The email of the user',
    example: 'example@gmail.com',
    required: true,
    uniqueItems: true,
    pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
    type: String,
    format: 'email',
  })
  userEmail: string;
  @ApiProperty({
    description: 'The password of the user',
    example: 'password123',
    required: true,
    minLength: 8,
    maxLength: 64,
    type: String,
    format: 'password',
    pattern:
      '^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])[A-Za-z\\d!@#$%^&*]{8,64}$',
  })
  userPassword: string;
  @ApiProperty({
    description: 'The first name of the user',
    example: 'John',
    required: true,
    minLength: 1,
    maxLength: 50,
    type: String,
  })
  firstName: string;
  @ApiProperty({
    description: 'The last name of the user',
    example: 'Doe',
    required: true,
    minLength: 1,
    maxLength: 50,
    type: String,
  })
  lastName: string;
  @ApiProperty({
    description: 'Indicates if the user is active',
    example: true,
    required: false,
    type: Boolean,
  })
  userActive: boolean;

  @ApiProperty({
    description: `The ID of the user type`,
    type: Number,
    required: true,
    example: 1,
  })
  userTypeId: number;

  constructor(
    userEmail: string,
    userPassword: string,
    firstName: string,
    lastName: string,
    userActive: boolean,
    userTypeId: number,
  ) {
    this.userEmail = userEmail;
    this.userPassword = userPassword;
    this.firstName = firstName;
    this.lastName = lastName;
    this.userActive = userActive;
    this.userTypeId = userTypeId;
  }
}
