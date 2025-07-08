import { ApiProperty } from '@nestjs/swagger';

export class CreateProcessReviewRequest {
  @ApiProperty({
    description: 'Unique identifier for the process review',
    example: 1,
    required: true,
    type: Number,
  })
  idProcess: number;

  @ApiProperty({
    description: 'Indicates if the process review is selected',
    example: false,
    required: false,
    type: Boolean,
  })
  isSelected: boolean;

  @ApiProperty({
    description: 'Indicates if the process review is active',
    example: true,
    required: false,
    type: Boolean,
  })
  isActive: boolean;

  constructor(
    idProcess: number,
    isSelected: boolean = false,
    isActive: boolean = true,
  ) {
    this.idProcess = idProcess;
    this.isSelected = isSelected;
    this.isActive = isActive;
  }
}
