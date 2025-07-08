import { ApiProperty } from '@nestjs/swagger';

export class UpdatePermissionRequest {
  @ApiProperty({
    description: 'The name of the permission',
    example: 'read:users',
    required: true,
    minLength: 1,
    maxLength: 100,
    type: String,
  })
  name: string;
  @ApiProperty({
    description: 'A brief description of the permission',
    example: 'Allows reading user data',
    required: false,
    minLength: 0,
    maxLength: 255,
    type: String,
  })
  description?: string;

  constructor(name: string, description?: string) {
    this.name = name;
    this.description = description;
  }
}
