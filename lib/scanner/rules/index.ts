import type { ScannerRule } from "../types";
import { jwtConfigurationRule, plaintextPasswordRule } from "./auth";
import { disabledSecurityRule, debugConfigurationRule, insecureHttpRule } from "./config";
import { permissiveCorsRule } from "./cors";
import { weakCryptographyRule } from "./crypto";
import { dangerousExecutionRule } from "./dangerous-execution";
import { dependencyConfigurationRule } from "./dependencies";
import { sqlInjectionRule } from "./injection";
import { hardcodedSecretsRule, sensitiveFilesRule } from "./secrets";

export const DEFAULT_RULES: ScannerRule[] = [
  sensitiveFilesRule,
  hardcodedSecretsRule,
  sqlInjectionRule,
  dangerousExecutionRule,
  permissiveCorsRule,
  debugConfigurationRule,
  jwtConfigurationRule,
  plaintextPasswordRule,
  weakCryptographyRule,
  insecureHttpRule,
  disabledSecurityRule,
  dependencyConfigurationRule,
];
