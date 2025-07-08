import { ApiProperty } from '@nestjs/swagger';

export class CreateTypeDocumentsRequest {
  @ApiProperty({
    description: 'Title of the type document',
    example: 'Passport',
    type: String,
    required: true,
  })
  title: string;

  @ApiProperty({
    description: 'Description of the type document',
    example: 'Official document for international travel',
    type: String,
    required: true,
  })
  description: string;

  constructor(title: string, description: string) {
    this.title = title;
    this.description = description;
  }
}
