import { ApiProperty } from '@nestjs/swagger';

export class UpdateProcessRequest {
  @ApiProperty({
    description: 'Unique identifier for the process',
    example: 'PRC-123456',
    required: true,
    type: String,
  })
  processNumber: string;

  @ApiProperty({
    description: 'Value associated with the process',
    example: 1000,
    required: true,
    type: Number,
  })
  value: number;

  @ApiProperty({
    description: 'Category of the process',
    example: 'Finance',
    required: true,
    type: String,
  })
  category: string;

  @ApiProperty({
    description: 'Description of the process',
    example: 'This is a sample process description.',
    required: true,
    type: String,
  })
  description: string;

  @ApiProperty({
    description: 'Estimated time for execution of the process',
    example: '2 weeks',
    required: true,
    type: String,
  })
  timeExecution: string;

  @ApiProperty({
    description: 'Object associated with the process',
    example: 'Contract Agreement',
    required: true,
    type: String,
  })
  processObject: string;

  @ApiProperty({
    description: 'Email of the manager responsible for the process',
    example: 'emailmanager@example.com',
    required: true,
    type: String,
  })
  emailManager: string;

  @ApiProperty({
    description: 'Full name of the manager responsible for the process',
    example: 'John Doe',
    required: true,
    type: String,
  })
  fullNameManager: string;

  @ApiProperty({
    description: 'Phone number of the manager responsible for the process',
    example: '+1234567890',
    required: true,
    type: String,
  })
  phoneManager: string;

  @ApiProperty({
    description: 'Status of the process represented by a numeric code',
    example: 1,
    required: true,
    type: Number,
  })
  statusProcess: number;

  @ApiProperty({
    description: 'Indicates if the process is active',
    example: true,
    required: false,
    type: Boolean,
  })
  isActive: boolean;

  @ApiProperty({
    description: 'ID of the entity associated with the process',
    example: 1,
    required: false,
    type: Number,
  })
  idEntity: number;

  @ApiProperty({
    description: 'ID of the status associated with the process',
    example: 1,
    required: false,
    type: Number,
  })
  idStatus: number;

  constructor(
    processNumber: string,
    value: number,
    category: string,
    description: string,
    timeExecution: string,
    processObject: string,
    emailManager: string,
    fullNameManager: string,
    phoneManager: string,
    statusProcess: number,
    isActive: boolean,
    idEntity: number,
    idStatus: number,
  ) {
    this.processNumber = processNumber;
    this.value = value;
    this.category = category;
    this.description = description;
    this.timeExecution = timeExecution;
    this.processObject = processObject;
    this.emailManager = emailManager;
    this.fullNameManager = fullNameManager;
    this.phoneManager = phoneManager;
    this.statusProcess = statusProcess;
    this.isActive = isActive ?? true;
    this.idEntity = idEntity ?? 1;
    this.idStatus = idStatus ?? 1;
  }
}
