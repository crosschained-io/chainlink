-- +goose Up
-- +goose StatementBegin
ALTER TABLE eth_txes ADD COLUMN simulate bool NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE eth_txes DROP COLUMN simulate;
-- +goose StatementEnd
