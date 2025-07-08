import { ApiProperty } from '@nestjs/swagger';
export class CreateRolePermissionRequest {
  @ApiProperty({
    example: 1,
    description: 'The ID of the role to which the permission is being assigned',
  })
  userTypeId: number;

  @ApiProperty({
    example: 1,
    description: 'The ID of the permission being assigned to the role',
  })
  permissionId: number;
}
