CREATE TABLE "auth_codes" (
"id" TEXT PRIMARY KEY,
"identifier" TEXT NOT NULL,
"code" TEXT NOT NULL,
"flow_id" char(36) NOT NULL,
"expires_at" DATETIME NOT NULL,
"attempts" INTEGER NOT NULL,
"created_at" DATETIME NOT NULL,
"updated_at" DATETIME NOT NULL
);
