/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.test.framework.certificate;

/**
 * Contains static certificates for the test cluster. 
 * Note: This is WIP and will be replaced by classes
 * that can generate certificates on the fly. This
 * class will be removed after that.
 */
public class Certificates {

	final static String ROOT_CA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
			+ "MIIDyjCCArKgAwIBAgIBATANBgkqhkiG9w0BAQsFADB1MRMwEQYKCZImiZPyLGQB\n"
			+ "GRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEaMBgGA1UECgwRRXhhbXBs\n"
			+ "ZSBDb20sIEluYy4xCzAJBgNVBAsMAkNBMRwwGgYDVQQDDBNyb290LmNhLmV4YW1w\n"
			+ "bGUuY29tMCAXDTIyMDYyMTE1MzIxM1oYDzIwNTIwNjEzMTUzMjEzWjB1MRMwEQYK\n"
			+ "CZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEaMBgGA1UE\n"
			+ "CgwRRXhhbXBsZSBDb20sIEluYy4xCzAJBgNVBAsMAkNBMRwwGgYDVQQDDBNyb290\n"
			+ "LmNhLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
			+ "v29KN4ZzIcMc0tiBcVD4nrG8lsnyKyyn3xx/NKDBugZhBrm1mhQcLq1BwRaJXO9W\n"
			+ "pKAc8MR66mYE+D91J5VgF80CTPOLeU+SGZSCgoc6SBdYYOCqikE/VJcVYU9oDL/h\n"
			+ "YnOJbmRYBt5q2e5UfMburaCX5p+o4lxiFHgDXK4V0gGlvDDrFdSVfBMYI9OWXH6u\n"
			+ "SddSYi1naOtjW5zD33pvg+0fDKu8AnAfbA2wUgm+Pf7VehnT9aw1wF62mdnYqK8n\n"
			+ "91VaNb4cKis++i7t302cg6P1FFQrjdlkZhRKotEVMGMUaVS1jkHImnasPtiGRCfj\n"
			+ "yx9AaCWhjdie15LKw+AcOQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MB8GA1Ud\n"
			+ "IwQYMBaAFDije6ThkSOvO2KbiPptckhPBT83MB0GA1UdDgQWBBQ4o3uk4ZEjrzti\n"
			+ "m4j6bXJITwU/NzAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggEBAC9K\n"
			+ "bHZGhHbQLm20ux1sLJeQI7YtlzmgM4iD9nofyhYXJZQQkUJ83IB+/vZndncUZS/o\n"
			+ "kGwEpqc+35P+SERq0FZ81K05WxTG9deSNk19VApfI0H+4JXp+ojrRrrTxzOtnOWl\n"
			+ "nijmqlbtNv8Vyu0UBtpGs5EczWEvl8wU48xxe0B4BjMA6eovI5l9qlapWaRF+Rqa\n"
			+ "pi4uDsT9pr3vlItdrAIrBQ8HV43X0xIMUQdYN1C5yZ/GLzPXmYUluddnCBvnmm+i\n"
			+ "qIXrjwK0o31xfuDzXLvJ19rqMgltDH/sbxTG/OcfBGohawT+IJX+fDgL2sx2V6M4\n"
			+ "PMAXXFEqLU4q+Hhxbyk=\n"
			+ "-----END CERTIFICATE-----\n"
			+ "";
	
	 final static String NODE_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
			+ "MIIEnTCCA4WgAwIBAgIGAYGG5Jv6MA0GCSqGSIb3DQEBCwUAMHUxEzARBgoJkiaJ\n"
			+ "k/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRowGAYDVQQKDBFF\n"
			+ "eGFtcGxlIENvbSwgSW5jLjELMAkGA1UECwwCQ0ExHDAaBgNVBAMME3Jvb3QuY2Eu\n"
			+ "ZXhhbXBsZS5jb20wIBcNMjIwNjIxMTUzMjE4WhgPMjA1MjA2MTMxNTMyMThaMHQx\n"
			+ "EzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRow\n"
			+ "GAYDVQQKDBFFeGFtcGxlIENvbSwgSW5jLjEMMAoGA1UECwwDT3BzMRowGAYDVQQD\n"
			+ "DBFub2RlMS5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n"
			+ "ggEBALIjArybeO9yxiqY+eNKvzS4sDjCAfJSIxLMoqfIHauUUhiLSlm7mPYgtDVT\n"
			+ "qhab+C2+4QAjTfzc7xPJxPHEgd3DE57e1JTb/EuLSBnEagQNep5UUW5+TUQv0JET\n"
			+ "ISQTnmaGt4iBVgGwBdY+Ab7TpN2lQchhz19/IGE0xkfm09t+5BPL/1DhaIByroEI\n"
			+ "Ip31atS+pXZaNy95Qo90yE3DJz+pNzZ68LYAapM9sXGzmjxGljVgaMqYjwcO70Qx\n"
			+ "KqkYR8/OjKotlNkXIlzGlL9n8sTpdpelC/wcR5VqwS3b8hP3COPwfYHTIgSzfB5Q\n"
			+ "xvzAFdpwLPU6FcRq4NEqIEhwPHMCAwEAAaOCATAwggEsMIGfBgNVHSMEgZcwgZSA\n"
			+ "FDije6ThkSOvO2KbiPptckhPBT83oXmkdzB1MRMwEQYKCZImiZPyLGQBGRYDY29t\n"
			+ "MRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEaMBgGA1UECgwRRXhhbXBsZSBDb20s\n"
			+ "IEluYy4xCzAJBgNVBAsMAkNBMRwwGgYDVQQDDBNyb290LmNhLmV4YW1wbGUuY29t\n"
			+ "ggEBMB0GA1UdDgQWBBQP30zmRDOu/y+HKpTpV1aXCgNH2DAMBgNVHRMBAf8EAjAA\n"
			+ "MA4GA1UdDwEB/wQEAwIF4DAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUH\n"
			+ "AwIwKQYDVR0RBCIwIIgFKgMEBQWCEW5vZGUxLmV4YW1wbGUuY29thwQKAAIBMA0G\n"
			+ "CSqGSIb3DQEBCwUAA4IBAQA61eEwLqlrXcDIrNPtTzR1rELymMdIzwroXHZsA8oT\n"
			+ "Er5UfOoBZ9sCG3cc3I85jKc7bhWi6r6IpEJS7sDjefFMWAW++4j+o70gdsmTqx1m\n"
			+ "2fKoDTXLtoNzEgg+qkjllBY6zNBt96xwvNR4J4U+KGAXdyDwyTR3xmqk2Wsgz1x4\n"
			+ "FVK1En/ylDfF7o6IyHL9M64ZFsjGfkGf25+roLjw/pF49Vk2GDXVYRsclXPJteAQ\n"
			+ "syEKwXQc9HEppVbq3cU7UOk2nUz+eRx9+pHOeGJDcfG3ikw/94wq9cXioNlBGdFt\n"
			+ "xrbeW/cCaq6bbLSWJfznyyVTqlbL5S1YIZGZkn/M6hCh\n"
			+ "-----END CERTIFICATE-----";
	
	 final static String NODE_KEY = "-----BEGIN PRIVATE KEY-----\n"
			+ "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCyIwK8m3jvcsYq\n"
			+ "mPnjSr80uLA4wgHyUiMSzKKnyB2rlFIYi0pZu5j2ILQ1U6oWm/gtvuEAI0383O8T\n"
			+ "ycTxxIHdwxOe3tSU2/xLi0gZxGoEDXqeVFFufk1EL9CREyEkE55mhreIgVYBsAXW\n"
			+ "PgG+06TdpUHIYc9ffyBhNMZH5tPbfuQTy/9Q4WiAcq6BCCKd9WrUvqV2WjcveUKP\n"
			+ "dMhNwyc/qTc2evC2AGqTPbFxs5o8RpY1YGjKmI8HDu9EMSqpGEfPzoyqLZTZFyJc\n"
			+ "xpS/Z/LE6XaXpQv8HEeVasEt2/IT9wjj8H2B0yIEs3weUMb8wBXacCz1OhXEauDR\n"
			+ "KiBIcDxzAgMBAAECggEAP5rpqL+YtGLWaDJcE3DGigQiA/od6NC0Lku8Dk2RbojU\n"
			+ "sWfW4ehuiv+NaPcZJd6GBIuB2mNAvveCNB4YwLzKJA06DcGBxS8xTCYM1gqAUjcf\n"
			+ "37W6p8nYO+8YuRxL+o44wmH62XZY59xakS9tvx3h4bRWoz5tZatGO/80h0rfvaDe\n"
			+ "OdB6grLl+NwYCE4R2/O7W77JyyFUEZfjtJv9NyOq2C9oScMiQ1I2JDGLOYnZ6ACw\n"
			+ "Cv60PTc22pQse3HDA6kaDDbh2DTLUOmu5vHgM0329xQxJIo9xmrsFdS0NeaJrZsC\n"
			+ "XXg6DuiMvWgYQBrReQhhl1IRbiL3Nh5u0OKwJp9eXQKBgQDYuqc+MdGw16ofe+Cq\n"
			+ "vxsHT7eo4pt8llkw9CmITZZNl4E+eg8YVku8N0RfA0Uk5V67YvIu02XH5o0Wpt+b\n"
			+ "Vyx/0ov4Nj6LG6UI+QgoXqsG4bqctEL0hGsPpKzjm1Cu4Tw+VhVcUa8iC2wWnD0G\n"
			+ "oK4lf/KR0K/NcuyKxWcXsgPtNQKBgQDSai+N09bh8Hjcxt865B073NRiLsSg+kiG\n"
			+ "4JXbWKzTZpy6eDH5ALFVeSurIajeBnw0jglvKXT5gfW6DXHfFBZUbsjZvtaFerkY\n"
			+ "jomvkEPFBdgwIA1Gv4sp9jxeeJpJon7XN6Mnt7wH1D+/bqWmqdJhyDHRHj7Qo9TT\n"
			+ "9g0vHVnABwKBgQC16qaq++JJEB2KY87HQ7YKQw2kQuHEh+bBwpCCCq4Y3wzrRkUZ\n"
			+ "ZoYXrERFhFcriyQjIgCq8WLDkm/nDZcvqtJ9UFuQsud4mHHEwFPqntvr4Nlk46I3\n"
			+ "4FaFQPKl8h6dTA3nPRac8SuR5giKSganY4QJkgYoAwUt7ENEkEHij9ff6QKBgQDG\n"
			+ "nnNrFodlWWBNTvCTH5c01bwpPepf5kGmB8ONfQQOvXK+Vg0d9fhvLWT6Mli71DVU\n"
			+ "Sqs/IkwH5hQ1XtGZeNWnN7giSpEnCHRGaO4xKiW+ikjLDMZbfR15K7VKm99QGLJQ\n"
			+ "p3U8XaSBY2oVYvW8/9rWcGoN8tXqjmus9Tr2uWbp6wKBgQC1seTXIQqSXi+GmtEh\n"
			+ "d5zCVr9M23Afvdo9rkk9FPvttpekKsrOGwBs8PmPYNqoBPRrtBhyh/DTGow+CI+6\n"
			+ "VBc7x4qp7U2RyB9vGqqN2kT9NR9tgiZQnW9Ca4LI3+/2/Z3v0umVbjbJevKHurT7\n"
			+ "gBU2A2Hcw3pf9AYnA5EQ1i061A==\n"
			+ "-----END PRIVATE KEY-----";
	
	final static String ADMIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
			+ "MIIEZTCCA02gAwIBAgIGAYGG5JwBMA0GCSqGSIb3DQEBCwUAMHUxEzARBgoJkiaJ\n"
			+ "k/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRowGAYDVQQKDBFF\n"
			+ "eGFtcGxlIENvbSwgSW5jLjELMAkGA1UECwwCQ0ExHDAaBgNVBAMME3Jvb3QuY2Eu\n"
			+ "ZXhhbXBsZS5jb20wIBcNMjIwNjIxMTUzMjIyWhgPMjA1MjA2MTMxNTMyMjJaMHMx\n"
			+ "EzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRow\n"
			+ "GAYDVQQKDBFFeGFtcGxlIENvbSwgSW5jLjEMMAoGA1UECwwDT3BzMRkwFwYDVQQD\n"
			+ "DBBraXJrLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n"
			+ "AQEAzvBuVRvn2gqHhF89+QV+QZC60+VFxvhfgVJkTAFt9bOsuH4vCiS0BcyNA3NK\n"
			+ "ZQ9wcEedbNqoKasXd3O4gN5DMsFfQ0Vxja5cbp2Ju6QHY0JS/ym1Mz6kvEHHZAhV\n"
			+ "TRbLuU9YYG8JgGTOU+Qnmh/WhMuWCVUpmAEgskczFxjSc96EwjYR7MXoYE1PlKPD\n"
			+ "BbEcdGN2DK8KV/vAfLKUK7ShyRwTHB8SF/ZWFCZmi1g8FB64zJjL80ZKOjVAZQBp\n"
			+ "hjOs9mBvoLbmECK1Vm8Ta6d9JmAYjQi3D3G96gPvm+MbrRLD5mtTYi/JrOgTSzO2\n"
			+ "E8sqxp0ox1ekKOjhZ8U5hHI4VQIDAQABo4H6MIH3MIGfBgNVHSMEgZcwgZSAFDij\n"
			+ "e6ThkSOvO2KbiPptckhPBT83oXmkdzB1MRMwEQYKCZImiZPyLGQBGRYDY29tMRcw\n"
			+ "FQYKCZImiZPyLGQBGRYHZXhhbXBsZTEaMBgGA1UECgwRRXhhbXBsZSBDb20sIElu\n"
			+ "Yy4xCzAJBgNVBAsMAkNBMRwwGgYDVQQDDBNyb290LmNhLmV4YW1wbGUuY29tggEB\n"
			+ "MB0GA1UdDgQWBBTl867wkyY5TAccXPphmYq7FczYcDAMBgNVHRMBAf8EAjAAMA4G\n"
			+ "A1UdDwEB/wQEAwIF4DAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAjANBgkqhkiG9w0B\n"
			+ "AQsFAAOCAQEAPUKca2dmBM8flsjx/gI9LoClIt2SnBUFJKncjJoPjvVp+T7tqLsE\n"
			+ "tUGMOnsKYtrpe76kmMgzKLpNnGbkGTL39UPoe+/ApxbMskU/rKCxKZ7N7iJwSdyu\n"
			+ "rGyHeJCwdwl+QnODMYvXf+An9ImNzUmosMMfd89xgz0VGlh5piisNwnw6E5gEUxJ\n"
			+ "+bNBZAihfVd8cy9FMCplq+PMsBw3caijsRoYx+OHI9neemHmxFDDeOPMHoA0iH9T\n"
			+ "KLvqPBFh045o60KNPSo2DrxALIwdVBxCmw2wlIL89ZpHnGTWw7mMoilB38xJq2AQ\n"
			+ "5E5Zh3ZnWW/JH1uBnnUMk1Eugw6QwrpD9Q==\n"
			+ "-----END CERTIFICATE-----\n";

	final static String ADMIN_KEY = "-----BEGIN PRIVATE KEY-----\n"
			+ "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDO8G5VG+faCoeE\n"
			+ "Xz35BX5BkLrT5UXG+F+BUmRMAW31s6y4fi8KJLQFzI0Dc0plD3BwR51s2qgpqxd3\n"
			+ "c7iA3kMywV9DRXGNrlxunYm7pAdjQlL/KbUzPqS8QcdkCFVNFsu5T1hgbwmAZM5T\n"
			+ "5CeaH9aEy5YJVSmYASCyRzMXGNJz3oTCNhHsxehgTU+Uo8MFsRx0Y3YMrwpX+8B8\n"
			+ "spQrtKHJHBMcHxIX9lYUJmaLWDwUHrjMmMvzRko6NUBlAGmGM6z2YG+gtuYQIrVW\n"
			+ "bxNrp30mYBiNCLcPcb3qA++b4xutEsPma1NiL8ms6BNLM7YTyyrGnSjHV6Qo6OFn\n"
			+ "xTmEcjhVAgMBAAECggEAIfvM+rAW/rEs+RmU+VCkH8tPSx4DO/4s3PV1YB/5+VgU\n"
			+ "3MVoHy/Q2oTxgWgNBxSmf+Ha4fX0mMculuDLo2ocufiUlt0QHVbNeiLn7AcvaWcK\n"
			+ "bznftncqoXnh7zUJIRxFv3xexJNniYzEb3Vv5XkmBu/SB11Tc9F3l59mrfvXD8zm\n"
			+ "8UZOwFfs9xe6e9vacufletr4Cwhes8lk5d1/3/7b6RgNZKrKU7Wi25oPWaboic4x\n"
			+ "WocIbsY27/kjUCJR/cNb47otV2o8hVPFv3l88D94XlSRZI7NduwikwOKznPbRL+H\n"
			+ "Dd/Zp5Cl4Tl7+btYV49EeYUtBBp/QkLmkM3Fz+HbfwKBgQDwGw3tHCIAW/G9Kg3Q\n"
			+ "O4neYdMwEMPUbR2eP/etbXlOmbYtP4JdulX5DImL4nML7A/3UtHMcMX5F8nPDBFH\n"
			+ "XCp5cPrN+ySNLVhRSbKokAvdcKwhvh2PUjOpPbJbM/Fv0U8cl/VtbyroZkkFSSDT\n"
			+ "yCRruxTg0pKE6b0d6VeVTyZ5YwKBgQDco1I+s+oCUwCilsXMkiDbyx9l3pqwPBh6\n"
			+ "JSwVLI8UJw/T1qMssE73EGpkhSNolZmUqDX8Yu7uGILLSe8F/86TiEwedpFu1tGx\n"
			+ "ASJzZ0V0itp+Ggr+Hqgq7v0nj2C5agXnL9mP54Xo+UiNFMw/sdWtAhj12eEZF4Px\n"
			+ "jRisjbGQ5wKBgERXjwk0fsEXaqFrPO9OYxm3QoNl4jeur0WB85+bj3G98srCTvsa\n"
			+ "tKnk1anJVPHJyWmeWzUTzGXwTXLvfmOPak+SxvCmUWsVwxOwJHgyOA5ZqcUY9hT7\n"
			+ "UtUTSJcJG+m17Ay5fBQgFlh79MDaZcuiJiu73l930Figp0HCTzmig9L9AoGAX+2q\n"
			+ "fpSes6/+4LIJAe6u1qEz34ivXNxkEAdFaVdcRfjNyt7RR0bIrma2u0mfoYMZqSaR\n"
			+ "glBJbb++bkCQ6dzUphRmdAA9LyG7PeguYFqQOiF86cLM8LvHhhMughq2hSbxthh5\n"
			+ "0TVqZWatApn+S9s3+ealj47RbaVpuoYMKknY4BUCgYAcmyP9ATmsJJKd5sx96aE7\n"
			+ "q2gihhRxmfGMUJgrHWCBp/k5PJu/63IcXfhpvh0gecbTQ0317iKJn9C/LDIXPHq9\n"
			+ "dkFDeG3JMSuitvtAWt5AByJOUe6VYWPYe/cnMd0r9DhnwfLleCx0ng2GTsrmajls\n"
			+ "BAkDTgXVUuhXPh7eCD3qBg==\n"
			+ "-----END PRIVATE KEY-----\n";
}
