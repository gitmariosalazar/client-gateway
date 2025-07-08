import {
  Body,
  Controller,
  Inject,
  Post,
  Req,
  Param,
  Put,
  Get,
  Delete,
  ParseIntPipe,
  OnModuleInit,
  UseGuards,
} from '@nestjs/common';
import { ClientKafka, RpcException } from '@nestjs/microservices';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { environments } from 'src/settings/environments/environments';
import { CreateDocumentRequest } from '../../domain/schemas/dto/request/create.document.request';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { UpdateDocumentRequest } from '../../domain/schemas/dto/request/update.document.request';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';

@Controller('documents')
@ApiTags('Documents')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class DocumentsGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly documentsClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.documentsClient.subscribeToResponseOf('documents.create');
    this.documentsClient.subscribeToResponseOf('documents.update');
    this.documentsClient.subscribeToResponseOf('documents.find-all');
    this.documentsClient.subscribeToResponseOf('documents.find-by-id');
    this.documentsClient.subscribeToResponseOf(
      'documents.find-by-type-document',
    );
    this.documentsClient.subscribeToResponseOf('documents.find-by-process-id');
    this.documentsClient.subscribeToResponseOf('documents.find-by-status');
    this.documentsClient.subscribeToResponseOf('documents.delete');
    await this.documentsClient.connect();
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new document ✅',
    description:
      'This endpoint allows you to create a new document in the system through the gateway.',
  })
  async createDocument(
    @Req() requst: Request,
    @Body() document: CreateDocumentRequest,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.documentsClient.send('documents.create', document),
      );

      return new ApiResponse(
        'Document created successfully',
        response,
        requst.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idDocument')
  @ApiOperation({
    summary: 'Method PUT - Update an existing document ✅',
    description:
      'This endpoint allows you to update an existing document in the system through the gateway.',
  })
  async updateDocument(
    @Req() requst: Request,
    @Body() document: UpdateDocumentRequest,
    @Param('idDocument', ParseIntPipe) idDocument: number,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.documentsClient.send('documents.update', { idDocument, document }),
      );

      return new ApiResponse(
        'Document updated successfully',
        response,
        requst.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Retrieve all documents ✅',
    description:
      'This endpoint allows you to retrieve all documents stored in the system through the gateway.',
  })
  async findAllDocuments(@Req() requst: Request): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.documentsClient.send('documents.find-all', {}),
      );

      return new ApiResponse(
        'Documents retrieved successfully',
        response,
        requst.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idDocument')
  @ApiOperation({
    summary: 'Method GET - Retrieve a document by ID ✅',
    description:
      'This endpoint allows you to retrieve a specific document by its ID through the gateway.',
  })
  async findDocumentById(
    @Req() requst: Request,
    @Param('idDocument', ParseIntPipe) idDocument: number,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.documentsClient.send('documents.find-by-id', { idDocument }),
      );

      return new ApiResponse(
        'Document retrieved successfully',
        response,
        requst.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-type-document/:idTypeDocument')
  @ApiOperation({
    summary: 'Method GET - Retrieve documents by type document ID ✅',
    description:
      'This endpoint allows you to retrieve documents associated with a specific type document ID through the gateway.',
  })
  async findDocumentsByTypeDocument(
    @Req() requst: Request,
    @Param('idTypeDocument', ParseIntPipe) idTypeDocument: number,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.documentsClient.send('documents.find-by-type-document', {
          idTypeDocument,
        }),
      );

      return new ApiResponse(
        'Documents retrieved by type document successfully',
        response,
        requst.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-process-id/:idProcess')
  @ApiOperation({
    summary: 'Method GET - Retrieve documents by process ID ✅',
    description:
      'This endpoint allows you to retrieve documents associated with a specific process ID through the gateway.',
  })
  async findDocumentsByProcessId(
    @Req() requst: Request,
    @Param('idProcess', ParseIntPipe) idProcess: number,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.documentsClient.send('documents.find-by-process-id', {
          idProcess,
        }),
      );

      return new ApiResponse(
        'Documents retrieved by process ID successfully',
        response,
        requst.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-status/:idStatus')
  @ApiOperation({
    summary: 'Method GET - Retrieve documents by status ID ✅',
    description:
      'This endpoint allows you to retrieve documents associated with a specific status ID through the gateway.',
  })
  async findDocumentsByStatusId(
    @Req() requst: Request,
    @Param('idStatus', ParseIntPipe) idStatus: number,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.documentsClient.send('documents.find-by-status', { idStatus }),
      );

      return new ApiResponse(
        'Documents retrieved by status ID successfully',
        response,
        requst.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idDocument')
  @ApiOperation({
    summary: 'Method DELETE - Delete a document by ID ✅',
    description:
      'This endpoint allows you to delete a specific document by its ID through the gateway.',
  })
  async deleteDocument(
    @Req() requst: Request,
    @Param('idDocument', ParseIntPipe) idDocument: number,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.documentsClient.send('documents.delete', { idDocument }),
      );

      return new ApiResponse(
        'Document deleted successfully',
        response,
        requst.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
