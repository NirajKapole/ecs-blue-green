#!/usr/bin/env bash
get_task_definition_arns() {
    aws ecs list-task-definitions \
        --region "$REGION" \
        --family-prefix "$TASK_NAME" \
        --status ACTIVE \
        --sort DESC \
        | jq -r '.taskDefinitionArns[]'

    aws ecs list-task-definitions \
        --region "$REGION" \
        --family-prefix "$TASK_NAME" \
        --status INACTIVE \
        --sort DESC \
        | jq -r '.taskDefinitionArns[]'
}

delete_task_definition() {
    local arn=$1

    aws ecs deregister-task-definition \
        --region "$REGION" \
        --task-definition "${arn}" > /dev/null

    aws ecs delete-task-definitions \
        --region "$REGION" \
        --task-definition "${arn}" > /dev/null
}

for arn in $(get_task_definition_arns)
do
    echo "Deregistering and deleting ${arn}..."
    delete_task_definition "${arn}"
done
