import { ApiProperty } from '@nestjs/swagger';

export class CreatePriorityRequest {
  @ApiProperty({
    description: 'Name of the priority',
    example: 'High',
    required: true,
    type: String,
  })
  name: string;

  @ApiProperty({
    description: 'Description of the priority',
    example: 'This is a high priority notification',
    required: true,
    type: String,
  })
  description: string;

  constructor(name: string, description: string) {
    this.name = name;
    this.description = description;
  }
}
