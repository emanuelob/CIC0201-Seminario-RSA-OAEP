import base64

class Base64Handler:
    @staticmethod
    def encode(data: bytes) -> str:
        """
        Codifica dados em BASE64.
        
        Args:
            data (bytes): Dados para codificar
            
        Returns:
            str: String em BASE64
        """
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def decode(data: str) -> bytes:
        """
        Decodifica dados de BASE64.
        
        Args:
            data (str): String em BASE64
            
        Returns:
            bytes: Dados decodificados
        """
        return base64.b64decode(data.encode('utf-8'))

    @staticmethod
    def format_signature(message: bytes, signature: bytes, public_key: tuple) -> str:
        """
        Formata a mensagem, assinatura e chave pública em um único string BASE64.
        
        Args:
            message (bytes): Mensagem original
            signature (bytes): Assinatura
            public_key (tuple): Chave pública (e, n)
            
        Returns:
            str: Documento assinado em formato BASE64
        """
        # Formato: [MENSAGEM]@[ASSINATURA]@[CHAVE_PUBLICA_E]@[CHAVE_PUBLICA_N]
        e, n = public_key
        components = [
            base64.b64encode(message).decode('utf-8'),
            base64.b64encode(signature).decode('utf-8'),
            str(e),
            str(n)
        ]
        return "@".join(components)

    @staticmethod
    def parse_signature(formatted_data: str) -> tuple:
        """
        Parse do documento assinado em BASE64.
        
        Args:
            formatted_data (str): Documento assinado em formato BASE64
            
        Returns:
            tuple: (mensagem, assinatura, chave_pública)
        """
        try:
            message_b64, signature_b64, e, n = formatted_data.split("@")
            message = base64.b64decode(message_b64)
            signature = base64.b64decode(signature_b64)
            public_key = (int(e), int(n))
            return message, signature, public_key
        except Exception as e:
            raise ValueError(f"Formato de assinatura inválido: {e}")