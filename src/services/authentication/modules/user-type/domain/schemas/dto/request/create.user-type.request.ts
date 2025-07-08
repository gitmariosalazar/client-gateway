import { ApiProperty } from '@nestjs/swagger';

export class CreateUserTypeRequest {
  @ApiProperty({
    example: 'Admin User',
    description: 'The name of the user type',
    uniqueItems: true,
  })
  name: string;
  @ApiProperty({
    example: 'Administrator with full access',
    description: 'A brief description of the user type',
    required: false,
  })
  description?: string;

  /**
   * Creates an instance of UserTypeRequest.
   * @param {string} name - The name of the user type.
   * @param {string} [description] - A brief description of the user type.
   */
  constructor(name: string, description?: string) {
    this.name = name;
    this.description = description;
  }
}
