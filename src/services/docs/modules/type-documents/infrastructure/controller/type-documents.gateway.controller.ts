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
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { CreateTypeDocumentsRequest } from '../../domain/schemas/dto/request/create.type-documents.request';
import { UpdateTypeDocumentsRequest } from '../../domain/schemas/dto/request/update.type-documents.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('type-documents')
@ApiTags('Type Documents')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class TypeDocumentsGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly typeDocumentsClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.typeDocumentsClient.subscribeToResponseOf('typeDocuments.create');
    this.typeDocumentsClient.subscribeToResponseOf('typeDocuments.update');
    this.typeDocumentsClient.subscribeToResponseOf('typeDocuments.find-all');
    this.typeDocumentsClient.subscribeToResponseOf('typeDocuments.find-by-id');
    this.typeDocumentsClient.subscribeToResponseOf(
      'typeDocuments.find-by-title',
    );
    this.typeDocumentsClient.subscribeToResponseOf('typeDocuments.delete');
    await this.typeDocumentsClient.connect();
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all type documents ✅',
    description: 'Retrieves a list of all type documents.',
  })
  async findAllTypeDocuments(@Req() request: Request): Promise<ApiResponse> {
    try {
      const typeDocuments = await sendKafkaRequest(
        this.typeDocumentsClient.send('typeDocuments.find-all', {}),
      );
      return new ApiResponse(
        'Type documents retrieved successfully',
        typeDocuments,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idTypeDocument')
  @ApiOperation({
    summary: 'Method GET - Find type document by ID ✅',
    description: 'Retrieves a type document by its ID.',
  })
  async findTypeDocumentById(
    @Req() request: Request,
    @Param('idTypeDocument', ParseIntPipe) idTypeDocument: number,
  ): Promise<ApiResponse> {
    try {
      const typeDocument = await sendKafkaRequest(
        this.typeDocumentsClient.send('typeDocuments.find-by-id', {
          idTypeDocument,
        }),
      );
      return new ApiResponse(
        'Type document retrieved successfully',
        typeDocument,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-title/:title')
  @ApiOperation({
    summary: 'Method GET - Find type document by title ✅',
    description: 'Retrieves a type document by its title.',
  })
  async findTypeDocumentByTitle(
    @Req() request: Request,
    @Param('title') title: string,
  ): Promise<ApiResponse> {
    try {
      const typeDocument = await sendKafkaRequest(
        this.typeDocumentsClient.send('typeDocuments.find-by-title', { title }),
      );
      return new ApiResponse(
        'Type document retrieved successfully',
        typeDocument,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new type document ✅',
    description: 'Creates a new type document.',
  })
  async createTypeDocument(
    @Req() request: Request,
    @Body() typeDocument: CreateTypeDocumentsRequest,
  ): Promise<ApiResponse> {
    try {
      const createdTypeDocument = await sendKafkaRequest(
        this.typeDocumentsClient.send('typeDocuments.create', typeDocument),
      );
      return new ApiResponse(
        'Type document created successfully',
        createdTypeDocument,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idTypeDocument')
  @ApiOperation({
    summary: 'Method PUT - Update a type document ✅',
    description: 'Updates an existing type document by its ID.',
  })
  async updateTypeDocument(
    @Req() request: Request,
    @Param('idTypeDocument', ParseIntPipe) idTypeDocument: number,
    @Body() typeDocument: UpdateTypeDocumentsRequest,
  ): Promise<ApiResponse> {
    try {
      const updatedTypeDocument = await sendKafkaRequest(
        this.typeDocumentsClient.send('typeDocuments.update', {
          idTypeDocument,
          typeDocument,
        }),
      );
      return new ApiResponse(
        'Type document updated successfully',
        updatedTypeDocument,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idTypeDocument')
  @ApiOperation({
    summary: 'Method DELETE - Delete a type document ✅',
    description: 'Deletes a type document by its ID.',
  })
  async deleteTypeDocument(
    @Req() request: Request,
    @Param('idTypeDocument', ParseIntPipe) idTypeDocument: number,
  ): Promise<ApiResponse> {
    try {
      const deletedTypeDocument = await sendKafkaRequest(
        this.typeDocumentsClient.send('typeDocuments.delete', {
          idTypeDocument,
        }),
      );
      return new ApiResponse(
        'Type document deleted successfully',
        deletedTypeDocument,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
