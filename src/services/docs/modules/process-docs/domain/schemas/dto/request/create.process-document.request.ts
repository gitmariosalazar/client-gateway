import { ApiProperty } from '@nestjs/swagger';

export class CreateProcessDocumentRequest {
  @ApiProperty({
    description: 'ID of the process',
    example: 1,
    type: Number,
    required: true,
  })
  idProcess: number;
  @ApiProperty({
    description: 'ID of the document',
    example: 1,
    type: Number,
    required: true,
  })
  idDocument: number;
  @ApiProperty({
    description: 'Observations for the process document',
    example: 'This is a sample observation.',
    type: String,
    required: true,
  })
  observations: string;

  constructor(idProcess: number, idDocument: number, observations: string) {
    this.idProcess = idProcess;
    this.idDocument = idDocument;
    this.observations = observations;
  }
}
