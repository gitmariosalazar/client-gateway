import {
  Body,
  Controller,
  Delete,
  Get,
  Inject,
  OnModuleInit,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ClientKafka, RpcException } from '@nestjs/microservices';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { environments } from 'src/settings/environments/environments';
import { CreateEntityRequest } from '../../domain/schemas/dto/request/create.entity.request';
import { firstValueFrom } from 'rxjs';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';

@Controller('entity')
@ApiTags('Entity')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class EntityGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly entityClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.entityClient.subscribeToResponseOf('entity.create');
    this.entityClient.subscribeToResponseOf('entity.update');
    this.entityClient.subscribeToResponseOf('entity.find-all');
    this.entityClient.subscribeToResponseOf('entity.find-by-id');
    this.entityClient.subscribeToResponseOf('entity.find-by-ruc');
    this.entityClient.subscribeToResponseOf('entity.delete');
    await this.entityClient.connect();
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new Entity ✅',
    description: 'Creates a new Entity.',
  })
  async createEntity(
    @Body() entity: CreateEntityRequest,
    @Req() request: Request,
  ): Promise<ApiResponse> {
    try {
      const entityCreated = await sendKafkaRequest(
        this.entityClient.send('entity.create', entity),
      );

      return new ApiResponse(
        'Entity created successfully',
        entityCreated,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idEntity')
  @ApiOperation({
    summary: 'Method PUT - Update an Entity ✅',
    description: 'Updates an existing Entity by its ID.',
  })
  async updateEntity(
    @Req() request: Request,
    @Body() entity: CreateEntityRequest,
    @Param('idEntity', ParseIntPipe) idEntity: number,
  ): Promise<ApiResponse> {
    try {
      const entityUpdated = await firstValueFrom(
        this.entityClient.send('entity.update', { idEntity, entity }),
      );

      return new ApiResponse(
        'Entity updated successfully',
        entityUpdated,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idEntity')
  @ApiOperation({
    summary: 'Method GET - Find Entity by ID ✅',
    description: 'Retrieves an Entity by its ID.',
  })
  async findEntityById(
    @Req() request: Request,
    @Param('idEntity', ParseIntPipe) idEntity: number,
  ): Promise<ApiResponse> {
    try {
      const entityFound = await firstValueFrom(
        this.entityClient.send('entity.find-by-id', { idEntity }),
      );

      return new ApiResponse(
        'Entity found successfully',
        entityFound,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-ruc/:ruc')
  @ApiOperation({
    summary: 'Method GET - Find Entity by RUC ✅',
    description: 'Retrieves an Entity by its RUC.',
  })
  async findEntityByRuc(
    @Req() request: Request,
    @Param('ruc') ruc: string,
  ): Promise<ApiResponse> {
    try {
      const entityFound = await firstValueFrom(
        this.entityClient.send('entity.find-by-ruc', { ruc }),
      );

      return new ApiResponse(
        'Entity found successfully',
        entityFound,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all Entities ✅',
    description: 'Retrieves a list of all Entities.',
  })
  async findAllEntities(@Req() request: Request): Promise<ApiResponse> {
    try {
      const entities = await firstValueFrom(
        this.entityClient.send('entity.find-all', {}),
      );

      return new ApiResponse(
        'Entities found successfully',
        entities,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idEntity')
  @ApiOperation({
    summary: 'Method DELETE - Delete an Entity ✅',
    description: 'Deletes an Entity by its ID.',
  })
  async deleteEntity(
    @Req() request: Request,
    @Param('idEntity', ParseIntPipe) idEntity: number,
  ): Promise<ApiResponse> {
    try {
      const entityDeleted = await firstValueFrom(
        this.entityClient.send('entity.delete', { idEntity }),
      );

      return new ApiResponse(
        'Entity deleted successfully',
        entityDeleted,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
