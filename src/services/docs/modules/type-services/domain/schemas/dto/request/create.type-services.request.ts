import { ApiProperty } from '@nestjs/swagger';

export class CreateTypeServicesRequest {
  @ApiProperty({
    example: 'Web Development',
    description: 'The name of the type of service',
    required: true,
    type: String,
  })
  public name: string;

  @ApiProperty({
    example:
      'Services related to web development including design, coding, and deployment.',
    description: 'A brief description of the type of service',
    required: true,
    type: String,
  })
  public description: string;

  constructor(name: string, description: string) {
    this.name = name;
    this.description = description;
  }
}
