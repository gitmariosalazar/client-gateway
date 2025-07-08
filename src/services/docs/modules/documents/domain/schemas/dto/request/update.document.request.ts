import { ApiProperty } from '@nestjs/swagger';

export class UpdateDocumentRequest {
  @ApiProperty({
    description: 'Unique identifier for the type of document',
    example: 1,
    required: true,
    type: Number,
  })
  idTypeDocument: number;

  @ApiProperty({
    description: 'Name of the document',
    example: 'Project Proposal',
    required: true,
    type: String,
  })
  documentName: string;

  @ApiProperty({
    description: 'Description of the document',
    example: 'This document outlines the project proposal details.',
    required: true,
    type: String,
  })
  documentDescription: string;

  @ApiProperty({
    description: 'Date when the document was requested',
    example: '2023-10-01T12:00:00Z',
    required: true,
    type: Date,
  })
  dateRequest: Date;

  @ApiProperty({
    description: 'Date when the document was received',
    example: '2023-10-02T12:00:00Z',
    required: true,
    type: Date,
  })
  dateReception: Date;

  @ApiProperty({
    description: 'Name of the manager responsible for the document',
    example: 'John Doe',
    required: true,
    type: String,
  })
  managerName: string;

  @ApiProperty({
    description:
      'Unique identifier for the process associated with the document',
    example: 123,
    required: true,
    type: Number,
  })
  idProcess: number;

  @ApiProperty({
    description: 'URL where the document can be accessed',
    example: 'https://example.com/documents/project-proposal.pdf',
    required: true,
    type: String,
  })
  documentUrl: string;

  @ApiProperty({
    description: 'Status identifier of the document',
    example: 1,
    required: true,
    type: Number,
  })
  idStatus: number;

  constructor(
    idTypeDocument: number,
    documentName: string,
    documentDescription: string,
    dateRequest: Date,
    dateReception: Date,
    managerName: string,
    idProcess: number,
    documentUrl: string,
    idStatus: number,
  ) {
    this.idTypeDocument = idTypeDocument;
    this.documentName = documentName;
    this.documentDescription = documentDescription;
    this.dateRequest = dateRequest;
    this.dateReception = dateReception;
    this.managerName = managerName;
    this.idProcess = idProcess;
    this.documentUrl = documentUrl;
    this.idStatus = idStatus;
  }
}
