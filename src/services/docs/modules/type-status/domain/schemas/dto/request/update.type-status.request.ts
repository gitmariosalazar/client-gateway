import { ApiProperty } from '@nestjs/swagger';

export class UpdateTypeStatusRequest {
  @ApiProperty({
    example: 'Active',
    description: 'Name of the type status',
    required: true,
    type: String,
  })
  name: string;

  @ApiProperty({
    example: 'This type status is active',
    description: 'Description of the type status',
    required: true,
    type: String,
  })
  description: string;

  constructor(name: string, description: string) {
    this.name = name;
    this.description = description;
  }

  toJSON(): Record<string, any> {
    return {
      name: this.name,
      description: this.description,
    };
  }
}
