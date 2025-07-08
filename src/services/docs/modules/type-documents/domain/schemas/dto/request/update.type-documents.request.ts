import { ApiProperty } from '@nestjs/swagger';

export class UpdateTypeDocumentsRequest {
  @ApiProperty({
    description: 'Title of the type document',
    example: 'Passport',
    type: String,
    required: false,
  })
  title: string;

  @ApiProperty({
    description: 'Description of the type document',
    example: 'Official document for international travel',
    type: String,
    required: false,
  })
  description: string;

  constructor(title: string, description: string) {
    this.title = title;
    this.description = description;
  }
}
