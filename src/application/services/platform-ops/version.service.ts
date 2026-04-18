import { Injectable, OnModuleInit } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class VersionService implements OnModuleInit {
  private versionData: any = {};

  onModuleInit() {
    let fileData = {};
    try {
      const filePath = path.join(process.cwd(), 'version.json');
      if (fs.existsSync(filePath)) {
        fileData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      }
    } catch (e) {
      // Ignore missing or malformed version.json
    }

    this.versionData = {
      version: process.env.VERSION || fileData['version'] || '0.0.0-dev',
      commit: process.env.GIT_COMMIT || fileData['commit'] || 'unknown',
      buildTime: process.env.BUILD_TIME || fileData['buildTime'] || new Date().toISOString(),
      env: process.env.NODE_ENV || 'development',
      instanceId: process.env.HOSTNAME || 'local-pod',
      region: process.env.AWS_REGION || process.env.REGION || 'local'
    };
  }

  getVersion() {
    return this.versionData;
  }
}
