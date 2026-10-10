using System;
using System.Collections.Generic;
using System.Linq;

namespace AegisPC.Security.Detection.YaraEngine
{
    public class YaraConditionParseException : Exception
    {
        public YaraConditionParseException(string message) : base(message) { }
        public YaraConditionParseException(string message, Exception inner) : base(message, inner) { }
    }

    public interface IYaraConditionNode
    {
        bool Evaluate(HashSet<string> matchedIdentifiers, int totalRulePatterns);
    }

    public sealed class IdentifierNode : IYaraConditionNode
    {
        public string Identifier { get; }

        public IdentifierNode(string identifier)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
        }

        public bool Evaluate(HashSet<string> matchedIdentifiers, int totalRulePatterns)
        {
            return matchedIdentifiers.Contains(Identifier);
        }

        public override string ToString() => Identifier;
    }

    public sealed class AnyOfThemNode : IYaraConditionNode
    {
        public bool Evaluate(HashSet<string> matchedIdentifiers, int totalRulePatterns)
        {
            return matchedIdentifiers.Count > 0;
        }

        public override string ToString() => "any of them";
    }

    public sealed class AllOfThemNode : IYaraConditionNode
    {
        public bool Evaluate(HashSet<string> matchedIdentifiers, int totalRulePatterns)
        {
            return totalRulePatterns > 0 && matchedIdentifiers.Count >= totalRulePatterns;
        }

        public override string ToString() => "all of them";
    }

    public sealed class NOfThemNode : IYaraConditionNode
    {
        public int N { get; }

        public NOfThemNode(int n)
        {
            N = n;
        }

        public bool Evaluate(HashSet<string> matchedIdentifiers, int totalRulePatterns)
        {
            return matchedIdentifiers.Count >= N;
        }

        public override string ToString() => $"{N} of them";
    }

    public sealed class NOfSetNode : IYaraConditionNode
    {
        public int N { get; }
        public IReadOnlyList<string> Identifiers { get; }

        public NOfSetNode(int n, IEnumerable<string> identifiers)
        {
            N = n;
            Identifiers = identifiers.ToList();
        }

        public bool Evaluate(HashSet<string> matchedIdentifiers, int totalRulePatterns)
        {
            int matched = 0;
            foreach (var id in Identifiers)
            {
                if (matchedIdentifiers.Contains(id))
                {
                    matched++;
                }
            }
            return matched >= N;
        }

        public override string ToString() => $"{N} of ({string.Join(", ", Identifiers)})";
    }

    public sealed class AndNode : IYaraConditionNode
    {
        public IYaraConditionNode Left { get; }
        public IYaraConditionNode Right { get; }

        public AndNode(IYaraConditionNode left, IYaraConditionNode right)
        {
            Left = left ?? throw new ArgumentNullException(nameof(left));
            Right = right ?? throw new ArgumentNullException(nameof(right));
        }

        public bool Evaluate(HashSet<string> matchedIdentifiers, int totalRulePatterns)
        {
            return Left.Evaluate(matchedIdentifiers, totalRulePatterns) &&
                   Right.Evaluate(matchedIdentifiers, totalRulePatterns);
        }

        public override string ToString() => $"({Left} and {Right})";
    }

    public sealed class OrNode : IYaraConditionNode
    {
        public IYaraConditionNode Left { get; }
        public IYaraConditionNode Right { get; }

        public OrNode(IYaraConditionNode left, IYaraConditionNode right)
        {
            Left = left ?? throw new ArgumentNullException(nameof(left));
            Right = right ?? throw new ArgumentNullException(nameof(right));
        }

        public bool Evaluate(HashSet<string> matchedIdentifiers, int totalRulePatterns)
        {
            return Left.Evaluate(matchedIdentifiers, totalRulePatterns) ||
                   Right.Evaluate(matchedIdentifiers, totalRulePatterns);
        }

        public override string ToString() => $"({Left} or {Right})";
    }

    public sealed class NotNode : IYaraConditionNode
    {
        public IYaraConditionNode Child { get; }

        public NotNode(IYaraConditionNode child)
        {
            Child = child ?? throw new ArgumentNullException(nameof(child));
        }

        public bool Evaluate(HashSet<string> matchedIdentifiers, int totalRulePatterns)
        {
            return !Child.Evaluate(matchedIdentifiers, totalRulePatterns);
        }

        public override string ToString() => $"not {Child}";
    }

    public sealed class BooleanLiteralNode : IYaraConditionNode
    {
        public bool Value { get; }

        public BooleanLiteralNode(bool value)
        {
            Value = value;
        }

        public bool Evaluate(HashSet<string> matchedIdentifiers, int totalRulePatterns)
        {
            return Value;
        }

        public override string ToString() => Value ? "true" : "false";
    }

    /// <summary>
    /// Mini-YARA koşul sözdizimini (AST) ayrıştıran ve değerlendiren belirteç tabanlı ayrıştırıcı.
    /// Desteklenen dil alt kümesi:
    /// - Tanımlayıcılar: $a, $s1
    /// - Boolean operatörler: and, or, not
    /// - Gruplama: ( )
    /// - Nicelik belirteçleri: any of them, all of them, N of them, N of ($a, $b)
    /// Desteklenmeyen veya geçersiz sözdizimi durumunda açıkça YaraConditionParseException fırlatır.
    /// </summary>
    public static class YaraConditionParser
    {
        private enum TokenType
        {
            Identifier,
            Number,
            Keyword,
            OpenParen,
            CloseParen,
            Comma,
            Eof
        }

        private sealed class Token
        {
            public TokenType Type { get; }
            public string Value { get; }
            public int Position { get; }

            public Token(TokenType type, string value, int position)
            {
                Type = type;
                Value = value;
                Position = position;
            }

            public override string ToString() => $"{Type}: '{Value}'";
        }

        public static IYaraConditionNode Parse(string conditionText, IEnumerable<string> definedIdentifiers)
        {
            if (string.IsNullOrWhiteSpace(conditionText))
            {
                throw new YaraConditionParseException("YARA kural koşul ifadesi boş olamaz.");
            }

            var validIdentifiers = new HashSet<string>(definedIdentifiers ?? Enumerable.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            var tokens = Tokenize(conditionText);
            int cursor = 0;

            IYaraConditionNode node = ParseOr(tokens, ref cursor, validIdentifiers);

            if (cursor < tokens.Count && tokens[cursor].Type != TokenType.Eof)
            {
                throw new YaraConditionParseException($"Koşul ifadesi sonrasında beklenmeyen ek belirteç: '{tokens[cursor].Value}' (Pozisyon: {tokens[cursor].Position})");
            }

            return node;
        }

        private static List<Token> Tokenize(string text)
        {
            var tokens = new List<Token>();
            int i = 0;
            int len = text.Length;

            while (i < len)
            {
                char c = text[i];

                if (char.IsWhiteSpace(c))
                {
                    i++;
                    continue;
                }

                if (c == '(')
                {
                    tokens.Add(new Token(TokenType.OpenParen, "(", i));
                    i++;
                    continue;
                }

                if (c == ')')
                {
                    tokens.Add(new Token(TokenType.CloseParen, ")", i));
                    i++;
                    continue;
                }

                if (c == ',')
                {
                    tokens.Add(new Token(TokenType.Comma, ",", i));
                    i++;
                    continue;
                }

                if (c == '$')
                {
                    int start = i;
                    i++;
                    while (i < len && (char.IsLetterOrDigit(text[i]) || text[i] == '_' || text[i] == '*'))
                    {
                        i++;
                    }
                    string ident = text.Substring(start, i - start);
                    tokens.Add(new Token(TokenType.Identifier, ident, start));
                    continue;
                }

                if (char.IsDigit(c))
                {
                    int start = i;
                    while (i < len && char.IsDigit(text[i]))
                    {
                        i++;
                    }
                    string num = text.Substring(start, i - start);
                    tokens.Add(new Token(TokenType.Number, num, start));
                    continue;
                }

                if (char.IsLetter(c) || c == '_')
                {
                    int start = i;
                    while (i < len && (char.IsLetterOrDigit(text[i]) || text[i] == '_'))
                    {
                        i++;
                    }
                    string word = text.Substring(start, i - start);
                    tokens.Add(new Token(TokenType.Keyword, word, start));
                    continue;
                }

                throw new YaraConditionParseException($"YARA koşulunda tanınmayan karakter: '{c}' (Pozisyon: {i})");
            }

            tokens.Add(new Token(TokenType.Eof, "<EOF>", len));
            return tokens;
        }

        private static IYaraConditionNode ParseOr(List<Token> tokens, ref int cursor, HashSet<string> validIdentifiers)
        {
            var left = ParseAnd(tokens, ref cursor, validIdentifiers);

            while (cursor < tokens.Count &&
                   tokens[cursor].Type == TokenType.Keyword &&
                   string.Equals(tokens[cursor].Value, "or", StringComparison.OrdinalIgnoreCase))
            {
                cursor++; // consume 'or'
                var right = ParseAnd(tokens, ref cursor, validIdentifiers);
                left = new OrNode(left, right);
            }

            return left;
        }

        private static IYaraConditionNode ParseAnd(List<Token> tokens, ref int cursor, HashSet<string> validIdentifiers)
        {
            var left = ParseNot(tokens, ref cursor, validIdentifiers);

            while (cursor < tokens.Count &&
                   tokens[cursor].Type == TokenType.Keyword &&
                   string.Equals(tokens[cursor].Value, "and", StringComparison.OrdinalIgnoreCase))
            {
                cursor++; // consume 'and'
                var right = ParseNot(tokens, ref cursor, validIdentifiers);
                left = new AndNode(left, right);
            }

            return left;
        }

        private static IYaraConditionNode ParseNot(List<Token> tokens, ref int cursor, HashSet<string> validIdentifiers)
        {
            if (cursor < tokens.Count &&
                tokens[cursor].Type == TokenType.Keyword &&
                string.Equals(tokens[cursor].Value, "not", StringComparison.OrdinalIgnoreCase))
            {
                cursor++; // consume 'not'
                var child = ParseNot(tokens, ref cursor, validIdentifiers);
                return new NotNode(child);
            }

            return ParsePrimary(tokens, ref cursor, validIdentifiers);
        }

        private static IYaraConditionNode ParsePrimary(List<Token> tokens, ref int cursor, HashSet<string> validIdentifiers)
        {
            if (cursor >= tokens.Count || tokens[cursor].Type == TokenType.Eof)
            {
                throw new YaraConditionParseException("Beklenmeyen koşul sonu (ifade eksik).");
            }

            var tok = tokens[cursor];

            // 1. Gruplama: ( Expression )
            if (tok.Type == TokenType.OpenParen)
            {
                cursor++; // consume '('
                var inner = ParseOr(tokens, ref cursor, validIdentifiers);
                if (cursor >= tokens.Count || tokens[cursor].Type != TokenType.CloseParen)
                {
                    throw new YaraConditionParseException("Kapanış parantezi ')' eksik.");
                }
                cursor++; // consume ')'
                return inner;
            }

            // 2. Boolean Literalleri: true / false
            if (tok.Type == TokenType.Keyword && string.Equals(tok.Value, "true", StringComparison.OrdinalIgnoreCase))
            {
                cursor++;
                return new BooleanLiteralNode(true);
            }
            if (tok.Type == TokenType.Keyword && string.Equals(tok.Value, "false", StringComparison.OrdinalIgnoreCase))
            {
                cursor++;
                return new BooleanLiteralNode(false);
            }

            // 3. Nicelik belirteçleri: any of ... / all of ... / N of ...
            if ((tok.Type == TokenType.Keyword && (string.Equals(tok.Value, "any", StringComparison.OrdinalIgnoreCase) ||
                                                  string.Equals(tok.Value, "all", StringComparison.OrdinalIgnoreCase))) ||
                tok.Type == TokenType.Number)
            {
                string quantifierKind = tok.Value.ToLowerInvariant();
                int targetN = -1;
                if (tok.Type == TokenType.Number)
                {
                    if (!int.TryParse(tok.Value, out targetN) || targetN < 0)
                    {
                        throw new YaraConditionParseException($"Geçersiz nicelik sayısı: '{tok.Value}'");
                    }
                }

                // Bir sonraki belirteç "of" mu kontrol et
                if (cursor + 1 < tokens.Count &&
                    tokens[cursor + 1].Type == TokenType.Keyword &&
                    string.Equals(tokens[cursor + 1].Value, "of", StringComparison.OrdinalIgnoreCase))
                {
                    cursor += 2; // consume quantifier and 'of'

                    if (cursor >= tokens.Count)
                    {
                        throw new YaraConditionParseException("'of' belirtecinden sonra hedef küme bekleniyor ('them' veya '( $a, $b )').");
                    }

                    // 3a. 'them'
                    if (tokens[cursor].Type == TokenType.Keyword && string.Equals(tokens[cursor].Value, "them", StringComparison.OrdinalIgnoreCase))
                    {
                        cursor++; // consume 'them'
                        if (quantifierKind == "any") return new AnyOfThemNode();
                        if (quantifierKind == "all") return new AllOfThemNode();
                        return new NOfThemNode(targetN);
                    }

                    // 3b. ( $a, $b, ... )
                    if (tokens[cursor].Type == TokenType.OpenParen)
                    {
                        cursor++; // consume '('
                        var idList = new List<string>();
                        while (cursor < tokens.Count && tokens[cursor].Type != TokenType.CloseParen)
                        {
                            if (tokens[cursor].Type == TokenType.Identifier)
                            {
                                string id = tokens[cursor].Value;
                                ValidateIdentifier(id, validIdentifiers);
                                idList.Add(id);
                                cursor++;

                                if (cursor < tokens.Count && tokens[cursor].Type == TokenType.Comma)
                                {
                                    cursor++; // consume ','
                                }
                            }
                            else
                            {
                                throw new YaraConditionParseException($"Küme parantezi içinde geçerli bir tanımlayıcı ($ident) bekleniyor, bulunan: '{tokens[cursor].Value}'");
                            }
                        }

                        if (cursor >= tokens.Count || tokens[cursor].Type != TokenType.CloseParen)
                        {
                            throw new YaraConditionParseException("Küme parantezi ')' kapatılmadı.");
                        }
                        cursor++; // consume ')'

                        if (quantifierKind == "any") return new NOfSetNode(1, idList);
                        if (quantifierKind == "all") return new NOfSetNode(idList.Count, idList);
                        return new NOfSetNode(targetN, idList);
                    }

                    throw new YaraConditionParseException($"'of' sonrasında desteklenmeyen hedef: '{tokens[cursor].Value}'");
                }
            }

            // 4. Tekil Tanımlayıcı: $s1
            if (tok.Type == TokenType.Identifier)
            {
                cursor++;
                ValidateIdentifier(tok.Value, validIdentifiers);
                return new IdentifierNode(tok.Value);
            }

            throw new YaraConditionParseException($"YARA kuralında desteklenmeyen koşul ifadesi veya anahtar kelime: '{tok.Value}' (Pozisyon: {tok.Position})");
        }

        private static void ValidateIdentifier(string id, HashSet<string> validIdentifiers)
        {
            if (validIdentifiers.Count > 0 && !validIdentifiers.Contains(id))
            {
                // Wildcard kontrolü ($s*)
                if (id.EndsWith("*"))
                {
                    string prefix = id.TrimEnd('*');
                    if (validIdentifiers.Any(v => v.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                    {
                        return;
                    }
                }

                throw new YaraConditionParseException($"Koşulda kullanılan '{id}' tanımlayıcısı kuralın 'strings' bölümünde tanımlanmamış.");
            }
        }
    }
}
