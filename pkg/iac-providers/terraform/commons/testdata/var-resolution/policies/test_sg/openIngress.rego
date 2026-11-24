package accurics

openIngress[retVal] {
    sg = input.aws_security_group[_]
    ingress = sg.config.ingress[_]
    cidrs = ingress.cidr_blocks[_]
    cidrs == "0.0.0.0/0"

    retVal := { "Id": sg.id }
}
