import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Inject,
  Req,
  Param,
  Body,
  ParseIntPipe,
  UseGuards,
  OnModuleInit,
} from '@nestjs/common';
import { ClientKafka, RpcException } from '@nestjs/microservices';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { environments } from 'src/settings/environments/environments';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { CreateRolePermissionRequest } from '../../domain/schemas/dto/request/create.role-permission.request';
import { UpdateRolePermissionRequest } from '../../domain/schemas/dto/request/update.role-permission.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('role-permission')
@ApiTags('role-permission')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class RolePermissionGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.authenticationKafkaClient)
    private readonly rolePermissionService: ClientKafka,
  ) {}

  async onModuleInit() {
    this.rolePermissionService.subscribeToResponseOf('role-permission.create');
    this.rolePermissionService.subscribeToResponseOf('role-permission.update');
    this.rolePermissionService.subscribeToResponseOf(
      'role-permission.find-all',
    );
    this.rolePermissionService.subscribeToResponseOf(
      'role-permission.find-by-id',
    );
    this.rolePermissionService.subscribeToResponseOf(
      'role-permission.find-by-user-type-id',
    );
    this.rolePermissionService.subscribeToResponseOf(
      'role-permission.find-by-permission-id',
    );
    this.rolePermissionService.subscribeToResponseOf('role-permission.delete');
    await this.rolePermissionService.connect();
    console.log(this.rolePermissionService['responsePatterns']);
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find All Role Permissions ✅',
    description:
      'This endpoint retrieves all role permissions from the system.',
  })
  async findAllRolePermissions(@Req() request: Request): Promise<ApiResponse> {
    try {
      const rolePermissions = await sendKafkaRequest(
        this.rolePermissionService.send('role-permission.find-all', {}),
      );
      return new ApiResponse(
        'Role permissions retrieved successfully',
        rolePermissions,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idRolePermission')
  @ApiOperation({
    summary: 'Method GET - Find Role Permission by ID ✅',
    description: 'This endpoint retrieves a role permission by its ID.',
  })
  async findByIdRolePermission(
    @Req() request: Request,
    @Param('idRolePermission', ParseIntPipe) idRolePermission: number,
  ): Promise<ApiResponse> {
    try {
      const rolePermission = await sendKafkaRequest(
        this.rolePermissionService.send('role-permission.find-by-id', {
          idRolePermission,
        }),
      );
      return new ApiResponse(
        'Role permission retrieved successfully',
        rolePermission,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-user-type/:userTypeId')
  @ApiOperation({
    summary: 'Method GET - Find Role Permissions by User Type ID ✅',
    description: 'This endpoint retrieves role permissions by user type ID.',
  })
  async findByUserTypeId(
    @Req() request: Request,
    @Param('userTypeId', ParseIntPipe) userTypeId: number,
  ): Promise<ApiResponse> {
    try {
      const rolePermissions = await sendKafkaRequest(
        this.rolePermissionService.send(
          'role-permission.find-by-user-type-id',
          { userTypeId },
        ),
      );
      return new ApiResponse(
        'Role permissions by user type ID retrieved successfully',
        rolePermissions,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-permission/:permissionId')
  @ApiOperation({
    summary: 'Method GET - Find Role Permissions by Permission ID ✅',
    description: 'This endpoint retrieves role permissions by permission ID.',
  })
  async findByPermissionId(
    @Req() request: Request,
    @Param('permissionId', ParseIntPipe) permissionId: number,
  ): Promise<ApiResponse> {
    try {
      const rolePermissions = await sendKafkaRequest(
        this.rolePermissionService.send(
          'role-permission.find-by-permission-id',
          { permissionId },
        ),
      );
      return new ApiResponse(
        'Role permissions by permission ID retrieved successfully',
        rolePermissions,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create Role Permission ✅',
    description: 'This endpoint creates a new role permission in the system.',
  })
  async createRolePermission(
    @Req() request: Request,
    @Body() rolePermissionRequest: CreateRolePermissionRequest,
  ): Promise<ApiResponse> {
    try {
      const createdRolePermission = await sendKafkaRequest(
        this.rolePermissionService.send(
          'role-permission.create',
          rolePermissionRequest,
        ),
      );
      return new ApiResponse(
        'Role permission created successfully',
        createdRolePermission,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idRolePermission')
  @ApiOperation({
    summary: 'Method PUT - Update Role Permission by ID ✅',
    description: 'This endpoint updates an existing role permission by its ID.',
  })
  async updateRolePermission(
    @Req() request: Request,
    @Param('idRolePermission', ParseIntPipe) idRolePermission: number,
    @Body() rolePermissionRequest: UpdateRolePermissionRequest,
  ): Promise<ApiResponse> {
    try {
      const updatedRolePermission = await sendKafkaRequest(
        this.rolePermissionService.send('role-permission.update', {
          idRolePermission,
          rolePermissionRequest,
        }),
      );
      return new ApiResponse(
        'Role permission updated successfully',
        updatedRolePermission,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idRolePermission')
  @ApiOperation({
    summary: 'Method DELETE - Delete Role Permission by ID ✅',
    description: 'This endpoint deletes a role permission by its ID.',
  })
  async deleteRolePermission(
    @Req() request: Request,
    @Param('idRolePermission', ParseIntPipe) idRolePermission: number,
  ): Promise<ApiResponse> {
    try {
      const deleted = await sendKafkaRequest(
        this.rolePermissionService.send('role-permission.delete', {
          idRolePermission,
        }),
      );
      return new ApiResponse(
        'Role permission deleted successfully',
        deleted,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
